openclaw gateway restart
sleep 3
openclaw status --deep
openclaw gateway health
openclaw doctor --non-interactive