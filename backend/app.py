from flask import Flask, jsonify, request
from flask_cors import CORS
import random
from datetime import datetime
import json

app = Flask(__name__)
CORS(app)

# Mock database for logs
LOGS_DATABASE = {
    'easy': [
        {
            'id': 1,
            'raw': '2024-03-15 14:23:45 [ALERT] Failed login attempt from IP 192.168.1.105 - User: admin - Attempts: 5',
            'source': 'SSH Server',
            'severity': 'Medium',
            'timestamp': '2024-03-15 14:23:45',
            'correctMitre': 'T1110',
            'correctMitigation': 'implement_mfa',
            'metadata': {
                'ip': '192.168.1.105',
                'user': 'admin',
                'service': 'SSH',
                'attempts': 5
            },
            'explanation': 'Failed login attempts indicate a brute force attack. The attacker is trying multiple passwords to gain unauthorized access.'
        },
        {
            'id': 2,
            'raw': '2024-03-15 10:15:23 [WARNING] Unusual port scanning activity detected from 10.0.0.50 targeting ports 1-1000',
            'source': 'IDS/IPS',
            'severity': 'Medium',
            'timestamp': '2024-03-15 10:15:23',
            'correctMitre': 'T1046',
            'correctMitigation': 'block_ip',
            'metadata': {
                'ip': '10.0.0.50',
                'ports': '1-1000',
                'service': 'Network',
                'pattern': 'Sequential'
            },
            'explanation': 'Port scanning is a reconnaissance technique used to discover open services on a target system.'
        }
    ],
    'medium': [
        {
            'id': 3,
            'raw': '2024-03-15 16:45:12 [CRITICAL] PowerShell execution with encoded command: powershell.exe -NoP -NonI -W Hidden -Enc WwBTAHkAcw==',
            'source': 'EDR System',
            'severity': 'High',
            'timestamp': '2024-03-15 16:45:12',
            'correctMitre': 'T1059.001',
            'correctMitigation': 'isolate_host',
            'metadata': {
                'process': 'powershell.exe',
                'flags': '-NoP -NonI -W Hidden',
                'encoding': 'Base64',
                'parent': 'winword.exe'
            },
            'explanation': 'Encoded PowerShell commands are often used by attackers to evade detection and execute malicious payloads.'
        },
        {
            'id': 4,
            'raw': '2024-03-15 09:30:45 [ALERT] Suspicious registry modification: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run - Added: UpdateCheck.exe',
            'source': 'Sysmon',
            'severity': 'High',
            'timestamp': '2024-03-15 09:30:45',
            'correctMitre': 'T1547.001',
            'correctMitigation': 'remove_persistence',
            'metadata': {
                'registry': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'action': 'Added',
                'value': 'UpdateCheck.exe',
                'process': 'cmd.exe'
            },
            'explanation': 'Registry modifications to Run keys establish persistence, ensuring malware executes on system startup.'
        }
    ],
    'hard': [
        {
            'id': 5,
            'raw': '2024-03-15 22:10:33 [CRITICAL] Process injection detected: svchost.exe -> lsass.exe | Memory allocation in remote process',
            'source': 'EDR System',
            'severity': 'Critical',
            'timestamp': '2024-03-15 22:10:33',
            'correctMitre': 'T1003.001',
            'correctMitigation': 'forensic_analysis',
            'metadata': {
                'source_process': 'svchost.exe',
                'target_process': 'lsass.exe',
                'technique': 'Process Injection',
                'risk': 'Credential Dumping'
            },
            'explanation': 'Process injection into LSASS is a common technique for stealing credentials from memory.'
        },
        {
            'id': 6,
            'raw': '2024-03-15 03:25:18 [CRITICAL] C2 Communication: Periodic beaconing to 185.220.101.45:443 | Jitter: 10%',
            'source': 'Network Monitor',
            'severity': 'Critical',
            'timestamp': '2024-03-15 03:25:18',
            'correctMitre': 'T1071.001',
            'correctMitigation': 'block_c2',
            'metadata': {
                'destination': '185.220.101.45:443',
                'pattern': 'Beaconing',
                'jitter': '10%',
                'user_agent': 'Mozilla/5.0'
            },
            'explanation': 'Periodic beaconing to external IPs indicates active command and control communication.'
        }
    ]
}

MITRE_OPTIONS = {
    'easy': [
        {'id': 'T1110', 'name': 'Brute Force', 'tactic': 'Credential Access'},
        {'id': 'T1046', 'name': 'Network Service Discovery', 'tactic': 'Discovery'},
        {'id': 'T1090', 'name': 'Proxy', 'tactic': 'Command and Control'},
        {'id': 'T1078', 'name': 'Valid Accounts', 'tactic': 'Initial Access'}
    ],
    'medium': [
        {'id': 'T1059.001', 'name': 'PowerShell', 'tactic': 'Execution'},
        {'id': 'T1547.001', 'name': 'Registry Run Keys', 'tactic': 'Persistence'},
        {'id': 'T1055', 'name': 'Process Injection', 'tactic': 'Defense Evasion'},
        {'id': 'T1070', 'name': 'Indicator Removal', 'tactic': 'Defense Evasion'}
    ],
    'hard': [
        {'id': 'T1003.001', 'name': 'LSASS Memory', 'tactic': 'Credential Access'},
        {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'},
        {'id': 'T1486', 'name': 'Data Encrypted for Impact', 'tactic': 'Impact'},
        {'id': 'T1027', 'name': 'Obfuscated Files', 'tactic': 'Defense Evasion'}
    ]
}

MITIGATION_OPTIONS = {
    'block_ip': {'text': 'Block IP address at firewall level', 'icon': '🔒'},
    'implement_mfa': {'text': 'Implement Multi-Factor Authentication', 'icon': '🔐'},
    'isolate_host': {'text': 'Isolate infected host from network', 'icon': '🚫'},
    'forensic_analysis': {'text': 'Perform forensic analysis and memory dump', 'icon': '🔍'},
    'remove_persistence': {'text': 'Remove persistence mechanisms', 'icon': '🗑️'},
    'block_c2': {'text': 'Block C2 communication channels', 'icon': '⛔'}
}

# Store user sessions
user_sessions = {}

def calculate_difficulty(score, streak, accuracy):
    """Calculate next difficulty based on performance"""
    performance_score = (score * 0.3) + (streak * 10) + (accuracy * 0.4)
    
    if performance_score < 50:
        return 'easy'
    elif performance_score < 150:
        return 'medium'
    else:
        return 'hard'

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

@app.route('/api/get-log', methods=['POST'])
def get_log():
    """Get a new log for analysis"""
    data = request.json
    difficulty = data.get('difficulty', 'easy')
    session_id = data.get('session_id', 'default')
    
    # Get random log for difficulty
    logs = LOGS_DATABASE.get(difficulty, LOGS_DATABASE['easy'])
    log = random.choice(logs)
    
    # Get MITRE options (shuffled)
    mitre_options = MITRE_OPTIONS.get(difficulty, MITRE_OPTIONS['easy']).copy()
    random.shuffle(mitre_options)
    
    # Store correct answer in session
    if session_id not in user_sessions:
        user_sessions[session_id] = {}
    
    user_sessions[session_id]['current_log'] = log['id']
    user_sessions[session_id]['correct_mitre'] = log['correctMitre']
    user_sessions[session_id]['correct_mitigation'] = log['correctMitigation']
    
    # Return log without correct answers
    response_log = {
        'id': log['id'],
        'raw': log['raw'],
        'source': log['source'],
        'severity': log['severity'],
        'timestamp': log['timestamp'],
        'metadata': log['metadata']
    }
    
    return jsonify({
        'log': response_log,
        'mitre_options': mitre_options,
        'mitigation_options': list(MITIGATION_OPTIONS.keys())[:4],
        'time_limit': 60 if difficulty == 'easy' else 45 if difficulty == 'medium' else 30
    })

@app.route('/api/validate', methods=['POST'])
def validate_answer():
    """Validate user's answer"""
    data = request.json
    session_id = data.get('session_id', 'default')
    selected_mitre = data.get('selected_mitre')
    selected_mitigation = data.get('selected_mitigation')
    time_remaining = data.get('time_remaining', 0)
    difficulty = data.get('difficulty', 'easy')
    
    # Get correct answers from session
    session = user_sessions.get(session_id, {})
    correct_mitre = session.get('correct_mitre')
    correct_mitigation = session.get('correct_mitigation')
    
    # Check if answers are correct
    is_mitre_correct = selected_mitre == correct_mitre
    is_mitigation_correct = selected_mitigation == correct_mitigation
    is_fully_correct = is_mitre_correct and is_mitigation_correct
    
    # Calculate points
    points = 0
    if is_fully_correct:
        base_points = {'easy': 10, 'medium': 25, 'hard': 50}
        time_bonus = int(time_remaining * 0.5)
        points = base_points.get(difficulty, 10) + time_bonus
    
    # Get explanation
    log_id = session.get('current_log')
    explanation = None
    for diff_level in LOGS_DATABASE.values():
        for log in diff_level:
            if log['id'] == log_id:
                explanation = log.get('explanation', 'Analysis complete.')
                break
    
    return jsonify({
        'is_correct': is_fully_correct,
        'is_mitre_correct': is_mitre_correct,
        'is_mitigation_correct': is_mitigation_correct,
        'correct_mitre': correct_mitre,
        'correct_mitigation': correct_mitigation,
        'points': points,
        'explanation': explanation,
        'mitre_details': next((m for m in MITRE_OPTIONS[difficulty] if m['id'] == correct_mitre), None),
        'mitigation_details': MITIGATION_OPTIONS.get(correct_mitigation)
    })

@app.route('/api/adapt-difficulty', methods=['POST'])
def adapt_difficulty():
    """Calculate adaptive difficulty based on performance"""
    data = request.json
    score = data.get('score', 0)
    streak = data.get('streak', 0)
    accuracy = data.get('accuracy', 100)
    
    next_difficulty = calculate_difficulty(score, streak, accuracy)
    
    return jsonify({
        'next_difficulty': next_difficulty,
        'reasoning': f'Based on score: {score}, streak: {streak}, accuracy: {accuracy}%'
    })

@app.route('/api/leaderboard', methods=['GET'])
def get_leaderboard():
    """Get top scores (mock data for now)"""
    mock_leaderboard = [
        {'rank': 1, 'name': 'CyberDefender', 'score': 1250, 'accuracy': 95},
        {'rank': 2, 'name': 'LogMaster', 'score': 1100, 'accuracy': 92},
        {'rank': 3, 'name': 'SecurityPro', 'score': 950, 'accuracy': 88},
        {'rank': 4, 'name': 'ThreatHunter', 'score': 800, 'accuracy': 85},
        {'rank': 5, 'name': 'SOCAnalyst', 'score': 750, 'accuracy': 82}
    ]
    
    return jsonify({'leaderboard': mock_leaderboard})

@app.route('/api/statistics', methods=['POST'])
def get_statistics():
    """Get user statistics"""
    data = request.json
    session_id = data.get('session_id', 'default')
    
    # Mock statistics for now
    stats = {
        'total_games': 15,
        'total_score': 850,
        'best_streak': 7,
        'average_accuracy': 85.5,
        'favorite_difficulty': 'medium',
        'achievements': ['First Log', 'Streak Master', 'Quick Analyzer']
    }
    
    return jsonify(stats)

if __name__ == '__main__':
    app.run(debug=True, port=5000)