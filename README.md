# QAS Engine for Terminal Applications

**QAServer (QAS)** is a high-speed, Python-powered SSH engine designed to turn simple scripts into interactive, remote terminal applications.

Unlike a standard SSH server that drops you into a Linux shell, QAS routes users directly into specific Python modules based on the username they use to connect. It handles networking, encryption, and session management, so you only need to focus on the Questions and Answers logic.

## Core Features

**Instant Routing**  
Connect via:
```bash
ssh <module_name>@your-ip -p 2222
```
The engine automatically loads `<module_name>.py`.

**QAS Bridge**  
Native support for SSH teleportation. Bridge users from the QAServer to other servers (Raspberry Pi, cloud VPS, etc.) with a single command.

**Persistent Session Memory**  
Use `c.data` to store variables (such as usernames or scores) that persist across functions and sessions.

**Hot Reloading**  
Edit your Python logic on the fly. The server reloads code on each connection or navigation—no restart required.

**Escape Hatch**  
Users can exit at any time using:
- ESC  
- CTRL + C  
- typing `exit`

## Quick Start

### 1. Requirements

Install dependencies:

```bash
pip install -r requirements.txt
```

### 2. Launch the Engine

```bash
python main.py
```

### 3. Test the Tutorial

Open a new terminal and connect:

```bash
ssh tutorial@localhost -p 2222
```

## Building a QAS Module

Create a file named `hello.py` in your root directory. This becomes your application:

```python
def run(c):
    c.send("=== Welcome to the QAS Engine ===\n")
    
    # 1. Ask a question
    name = c.force_answer("What is your name? ")
    c.data['name'] = name  # Save to memory
    
    # 2. Logic-based navigation
    c.send(f"Hello {name}! Moving to password check...\n")
    check_pass(c)


def check_pass(c):
    pw = c.force_answer("Enter the secret code: ")
    
    if pw == "1234":
        c.send("Correct! Access granted.\n")
    else:
        c.send("Wrong code! Try again.\n")
        # Loop or re-route
        c.keeponline("check_pass")
```
