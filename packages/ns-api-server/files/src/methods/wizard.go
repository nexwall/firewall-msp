/*
Copyright (C) 2026 Nexwall
SPDX-License-Identifier: GPL-2.0-only
*/

package methods

import (
	"encoding/json"
	"io"
	"net/http"
	"os/exec"

	"github.com/Jeffail/gabs/v2"
	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/NethServer/nethsecurity-api/response"
)

// Deliberately unauthenticated - see ns.wizard's own set-password-unauth for the actual
// safety boundary (refuses once the wizard is complete, checked server-side against UCI on
// every call). These two handlers exist only so the wizard is reachable before a session
// exists at all; neither one accepts a caller-chosen ubus path or method the way the
// authenticated UBusCallAction does - each calls exactly one hardcoded action.

func callNsWizard(action string, payload []byte) (*gabs.Container, int, error) {
	cmd := exec.Command("/usr/libexec/rpcd/ns.wizard", "call", action)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if payload != nil {
		io.WriteString(stdin, string(payload))
	}
	stdin.Close()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	parsed, err := gabs.ParseJSON(out)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	return parsed, http.StatusOK, nil
}

// GET /api/wizard/status - just the completion flag, safe to expose with no auth: nothing
// sensitive in it, and it's what the frontend needs to decide whether to show the wizard
// before any login has happened.
func WizardStatus(c *gin.Context) {
	parsed, status, err := callNsWizard("get", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusBadRequest{
			Code:    500,
			Message: "wizard status unavailable",
			Data:    err.Error(),
		}))
		return
	}
	c.JSON(status, parsed.Data())
}

// POST /api/wizard/skip - "Skip wizard" before any login. ns.wizard refuses once the wizard is complete (checked fresh on
// every call) and commits the flag itself, there is no session that could do it later.
func WizardSkip(c *gin.Context) {
	parsed, _, err := callNsWizard("skip-unauth", []byte("{}"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusBadRequest{
			Code:    500,
			Message: "wizard call failed",
			Data:    err.Error(),
		}))
		return
	}
	if parsed.Exists("validation") || parsed.Exists("error") {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "wizard_skip_failed",
			Data:    parsed,
		}))
		return
	}
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "wizard skipped",
	}))
}

type wizardSetPasswordRequest struct {
	Password        string `json:"password" binding:"required"`
	PasswordConfirm string `json:"password_confirm" binding:"required"`
}

// POST /api/wizard/set-password - see the safety note above the file's callNsWizard: the
// actual refusal-once-complete check lives in ns.wizard, checked fresh on every call, not
// cached or trusted from anywhere in this handler.
func WizardSetPassword(c *gin.Context) {
	var req wizardSetPasswordRequest
	if err := c.ShouldBindBodyWith(&req, binding.JSON); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "request fields malformed",
			Data:    err.Error(),
		}))
		return
	}

	payload, _ := json.Marshal(req)
	parsed, _, err := callNsWizard("set-password-unauth", payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusBadRequest{
			Code:    500,
			Message: "wizard call failed",
			Data:    err.Error(),
		}))
		return
	}

	if parsed.Exists("validation") {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "validation_failed",
			Data:    parsed,
		}))
		return
	}
	if parsed.Exists("error") {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "wizard_set_password_failed",
			Data:    parsed,
		}))
		return
	}

	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "password set",
	}))
}
