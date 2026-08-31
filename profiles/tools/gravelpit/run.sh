#!/bin/bash
# Profile: gravelpit managing itself from inside its own sandbox.
#
# gravelpit policy lint/reload/eval resolve the policy dir by reading
# ~/.config/gravelpit/config.yaml when --policy-dir is not given. That read
# goes through the very sandbox being managed, so this profile catches the
# case where the CLI cannot read its own config from inside itself.
[ "$1" = "--check" ] && { [ -n "$GRAVELPIT_BIN" ] && [ -x "$GRAVELPIT_BIN" ]; exit; }
"$GRAVELPIT_BIN" policy lint
"$GRAVELPIT_BIN" policy reload
"$GRAVELPIT_BIN" policy eval read "$HOME/.bashrc"
