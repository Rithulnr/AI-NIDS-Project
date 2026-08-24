import subprocess
import time

blocked_ips = set()
rate_limited_ips = {}
tarpitted_ips = set()

def block_ip(ip):
    # Safety: Don't block loopback by default    # SAFETY: Never block localhost!
    if ip == "127.0.0.1":
        print(f"[NEUTRALIZE] Loopback IP {ip} ignored for safety.")
        # --- DEMO MODE: Create a dummy rule so the user can see the UI working ---
        rule_name = f"IDS_Block_1.2.3.4"
        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip=1.2.3.4'
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return "IGNORED (SAFETY) - MOCK RULE CREATED"

    rule_name = f"IDS_Block_{ip}"
    # Suppress output to prevent terminal spam
    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    blocked_ips.add(ip)

def unblock_ip(ip):
    rule_name = f"IDS_Block_{ip}"
    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if ip in blocked_ips:
        blocked_ips.remove(ip)

def get_blocked_ips():
    return list(blocked_ips)

def get_tarpitted_ips():
    return list(tarpitted_ips)

def tarpit_ip(ip):
    if ip == "127.0.0.1":
        print(f"[NEUTRALIZE] Tarpitting localhost (Demo Mode).")
        
    print(f"[TARPIT] Rerouting attacker {ip} to the AI Tarpit (Port 5051).")
    # In a real environment, we would use iptables PREROUTING or Windows netsh portproxy.
import requests

def revoke_identity(ip):
    try:
        # Call the IdP Simulator to revoke sessions
        response = requests.post("http://127.0.0.1:5052/api/revoke_by_ip", json={"ip": ip}, timeout=1)
        if response.status_code == 200:
            print(f"[ZERO-TRUST] Revoked identity sessions for IP {ip}")
    except Exception as e:
        print(f"[ZERO-TRUST] Failed to contact IdP for revocation: {e}")

import random
import numpy as np
import json
import os

# --- Q-Learning Agent ---
class QLearningAgent:
    def __init__(self, states_num=5, actions_num=5, alpha=0.1, gamma=0.9, epsilon=0.2):
        self.q_table = np.zeros((states_num, actions_num))
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon
        self.actions = ["ALLOW", "MONITOR", "RATE_LIMIT", "TARPIT", "BLOCK"]
        self.q_table_path = "q_table.json"
        self._load_q_table()

    def get_state(self, risk):
        if risk <= 0.45: return 0    # LOW
        elif risk <= 0.65: return 1  # MODERATE
        elif risk <= 0.85: return 2  # HIGH
        elif risk <= 0.95: return 3  # CRITICAL
        else: return 4               # EXTREME

    def choose_action(self, state):
        if random.uniform(0, 1) < self.epsilon:
            return random.randint(0, len(self.actions) - 1)  # Explore
        return np.argmax(self.q_table[state])  # Exploit

    def simulate_reward(self, state, action):
        # Simulated Expert Reward Function
        # states: 0=LOW, 1=MOD, 2=HIGH, 3=CRIT, 4=EXTR
        # actions: 0=ALLOW, 1=MONITOR, 2=RATE_LIMIT, 3=TARPIT, 4=BLOCK
        reward_matrix = [
            # ALLOW, MON, RL, TARPIT, BLOCK
            [ 10,   5,  -10, -20,   -50], # LOW Risk
            [  5,  10,    5, -10,   -30], # MOD Risk
            [-10,   5,   10,   5,   -10], # HIGH Risk
            [-50, -10,    5,  10,     5], # CRIT Risk
            [-100,-50,  -10,   5,    10]  # EXTR Risk
        ]
        return reward_matrix[state][action]

    def update(self, state, action, reward, next_state):
        best_next_action = np.argmax(self.q_table[next_state])
        td_target = reward + self.gamma * self.q_table[next_state][best_next_action]
        td_error = td_target - self.q_table[state][action]
        self.q_table[state][action] += self.alpha * td_error
        self._save_q_table()

    def _save_q_table(self):
        try:
            with open(self.q_table_path, "w") as f:
                json.dump(self.q_table.tolist(), f)
        except Exception:
            pass

    def _load_q_table(self):
        if os.path.exists(self.q_table_path):
            try:
                with open(self.q_table_path, "r") as f:
                    self.q_table = np.array(json.load(f))
            except Exception:
                pass

rl_agent = QLearningAgent()

def neutralize(ip, risk):
    current_time = time.time()
    
    # 1. Get State
    state = rl_agent.get_state(risk)
    
    # 2. Choose Action
    action_idx = rl_agent.choose_action(state)
    action_str = rl_agent.actions[action_idx]
    
    # 3. Simulate Environment Feedback & Update Q-Table
    # Assuming the risk remains the same for the next state immediately after, to simplify.
    reward = rl_agent.simulate_reward(state, action_idx)
    rl_agent.update(state, action_idx, reward, state)

    # 4. Execute Action
    if action_str == "BLOCK":
        if ip not in blocked_ips:
            block_ip(ip)
            revoke_identity(ip)
            print(f"[RL NEUTRALIZATION] Blocked {ip}. (Risk: {risk:.2f}, Reward: {reward})")
            
    elif action_str == "TARPIT":
        if ip not in tarpitted_ips:
            tarpit_ip(ip)
            revoke_identity(ip)
            print(f"[RL NEUTRALIZATION] Tarpitted {ip}. (Risk: {risk:.2f}, Reward: {reward})")
            
    elif action_str == "RATE_LIMIT":
        if ip not in rate_limited_ips or (current_time - rate_limited_ips[ip] > 60):
            rate_limited_ips[ip] = current_time
            print(f"[RL NEUTRALIZATION] Rate limiting {ip}. (Risk: {risk:.2f}, Reward: {reward})")
            
    elif action_str == "MONITOR":
        pass # Just monitoring
        
    elif action_str == "ALLOW":
        pass

    return action_str