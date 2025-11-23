package utils

import "log/slog"

func SendVerificationEmail(email string, link string, traceID string) {
	// Placeholder for sending email
	slog.Info("Sending verification email", "to", email, "link", link, "trace_id", traceID)
}
