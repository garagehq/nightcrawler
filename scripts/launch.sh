#!/bin/bash
# Nightcrawler — Launch in tmux session
NC_HOME="${NC_HOME:-/opt/nightcrawler}"
SESSION="nightcrawler"

# Kill existing session if any
tmux kill-session -t "$SESSION" 2>/dev/null

# Create new tmux session
tmux new-session -d -s "$SESSION" -n agent

# Window 0: Agent (main)
tmux send-keys -t "$SESSION:agent" "cd $NC_HOME && bash scripts/start.sh" Enter

# Window 1: LLM logs
tmux new-window -t "$SESSION" -n llm
tmux send-keys -t "$SESSION:llm" "tail -f /tmp/llama-server.log 2>/dev/null || echo 'Waiting for llama-server...'" Enter

# Window 2: Proxy logs
tmux new-window -t "$SESSION" -n proxy
tmux send-keys -t "$SESSION:proxy" "tail -f /tmp/scope-proxy.log 2>/dev/null || echo 'Waiting for proxy...'" Enter

# Window 3: Shell
tmux new-window -t "$SESSION" -n shell
tmux send-keys -t "$SESSION:shell" "cd $NC_HOME" Enter

# Select agent window and attach
tmux select-window -t "$SESSION:agent"
tmux attach-session -t "$SESSION"
