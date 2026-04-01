"""
TUTORIAL / TEMPLATE MODULE
This file explains how to build apps for the SSH Server.
To use: ssh tutorial@your-ip -p 2222
"""

def run(c):
    """
    'run' is the entry point. 
    'c' is the connection object (SSHInterface).
    """
    c.send("=== WELCOME TO THE SSH-APP TUTORIAL ===\n")
    c.send("This module will show you what this engine can do.\n")
    
    # 1. SIMPLE INPUT
    # c.answer() returns whatever the user types. Can be empty.
    c.send("\n1. Simple Input:\n")
    name = c.answer("What is your name? (Can be empty): ")
    c.send(f"You typed: '{name}'\n")

    # 2. FORCED INPUT
    # c.force_answer() loops until the user actually types something.
    c.send("\n2. Forced Input:\n")
    c.data['user_val'] = c.force_answer("Type something (Required!): ")
    
    # 3. SESSION MEMORY (c.data)
    # c.data is a dictionary that survives even if you 'jump' or restart.
    c.send(f"\n3. Memory: Saved '{c.data['user_val']}' to session storage.\n")
    
    # Move to the next "Step"
    show_navigation(c)

def show_navigation(c):
    c.send("\n=== 4. NAVIGATION & JUMPING ===\n")
    c.send("You can jump to any function using c.keeponline('function_name')\n")
    c.send("1) Restart this section\n")
    c.send("2) Test the SSH Bridge (Jump to another server)\n")
    c.send("3) Exit the tutorial\n")
    
    choice = c.force_answer("Select 1, 2, or 3: ")

    if choice == "1":
        c.send("Restarting this function...\n")
        # keeponline() with a string calls that specific function name.
        c.keeponline("show_navigation")

    elif choice == "2":
        # 5. SSH BRIDGING
        # This connects the current user to a different SSH server.
        c.send("\n=== 5. SSH BRIDGING ===\n")
        host = c.force_answer("Target IP: ")
        user = c.force_answer("Target Username: ")
        pwd = c.force_answer("Target Password: ")
        
        c.send("Attempting to bridge... (Type 'exit' or use ESC to return here)\n")
        c.bridge_to_remote(host, user, pwd)
        
        # After the bridge closes, we come back here
        c.send("\nWelcome back from the bridge!\n")
        c.keeponline("show_navigation")

    elif choice == "3":
        c.send("\nThanks for using the tutorial. Goodbye!\n")
        # Returning None (or just reaching the end) closes the connection.
        return None

    else:
        c.send("Invalid choice! Let's try again.\n")
        # keeponline() without a string restarts from run(c).
        c.keeponline()