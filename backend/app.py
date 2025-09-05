"""
ADAPTIVE LOG ANALYST - BACKEND FLASK
Server API REST che gestisce la logica di gioco e la validazione delle risposte
Simula le funzionalità di ByteBoo per l'analisi dei log di sicurezza
"""

from flask import Flask, jsonify, request   # Framework web e utilities
from flask_cors import CORS                 # Cross-Origin Resource Sharing per permettere chiamate dal frontend
import random                               # Per selezione casuale dei log
from datetime import datetime               # Per timestamp
import json                                 # Per gestione dati JSON

# ============================================================================
# INIZIALIZZAZIONE FLASK
# ============================================================================

app = Flask(__name__)
CORS(app)               # Abilita CORS per permettere al frontend React di comunicare con Flask

# ============================================================================
# DATABASE MOCK DEI LOG
# ============================================================================

"""
Simuliamo un database con dizionari Python
Ogni log rappresenta un evento di sicurezza reale che potrebbe apparire in un SIEM
"""

LOGS_DATABASE = {
    'easy': [
        {
            'id': 1,
            # Log grezzo come apparirebbe nel sistema
            'raw': '2024-03-15 14:23:45 [ALERT] Failed login attempt from IP 192.168.1.105 - User: admin - Attempts: 5',
            'source': 'SSH Server',                     # Sistema che ha generato il log
            'severity': 'Medium',                       # Livello di gravità dell'evento
            'timestamp': '2024-03-15 14:23:45',
            'correctMitre': 'T1110',                    # Tecnica MITRE corretta (Brute Force)
            'correctMitigation': 'implement_mfa',       # Mitigazione corretta
            'metadata': { # Dati strutturati estratti dal log
                'ip': '192.168.1.105',
                'user': 'admin',
                'service': 'SSH',
                'attempts': 5
            },
            # Spiegazione educativa per l'utente
            'explanation': 'Failed login attempts indicate a brute force attack. The attacker is trying multiple passwords to gain unauthorized access.'
        },
        {
            'id': 2,
            'raw': '2024-03-15 10:15:23 [WARNING] Unusual port scanning activity detected from 10.0.0.50 targeting ports 1-1000',
            'source': 'IDS/IPS',
            'severity': 'Medium',
            'timestamp': '2024-03-15 10:15:23',
            'correctMitre': 'T1046',                    # Tecnica MITRE corretta (Network Service Discovery)
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
            'correctMitre': 'T1059.001',                 # Tecnica MITRE corretta (PowerShell execution)
            'correctMitigation': 'isolate_host',
            'metadata': {
                'process': 'powershell.exe',
                'flags': '-NoP -NonI -W Hidden',         # Flags sospetti che bypassano policy
                'encoding': 'Base64',
                'parent': 'winword.exe'                  # Word che lancia PowerShell = molto sospetto
            },
            'explanation': 'Encoded PowerShell commands are often used by attackers to evade detection and execute malicious payloads.'
        },
        {
            'id': 4,
            'raw': '2024-03-15 09:30:45 [ALERT] Suspicious registry modification: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run - Added: UpdateCheck.exe',
            'source': 'Sysmon',
            'severity': 'High',
            'timestamp': '2024-03-15 09:30:45',
            'correctMitre': 'T1547.001',                 # Tecnica MITRE corretta (Registry Run Keys (Persistence))
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
            'correctMitre': 'T1003.001',                   # Tecnica MITRE corretta (LSASS Memory (Credential Dumping))
            'correctMitigation': 'forensic_analysis',
            'metadata': {
                'source_process': 'svchost.exe',
                'target_process': 'lsass.exe',             # LSASS contiene credenziali in memoria
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
            'correctMitre': 'T1071.001',                    # Tecnica MITRE corretta (Web Protocols (C&C))
            'correctMitigation': 'block_c2',
            'metadata': {
                'destination': '185.220.101.45:443',
                'pattern': 'Beaconing',                     # Pattern periodico = C2
                'jitter': '10%',                            # Variazione temporale per evadere detection
                'user_agent': 'Mozilla/5.0'
            },
            'explanation': 'Periodic beaconing to external IPs indicates active command and control communication.'
        }
    ]
}

# ============================================================================
# DATABASE TECNICHE MITRE ATT&CK
# ============================================================================

"""
Framework MITRE ATT&CK: catalogo di tecniche usate dagli attaccanti
Ogni tecnica ha un ID univoco (es. T1110) e appartiene a una tattica
"""

MITRE_OPTIONS = {
    'easy': [
        {
            'id': 'T1110',                  # ID unico della tecnica
            'name': 'Brute Force',          # Nome descrittivo
            'tactic': 'Credential Access'   # Fase dell'attacco (tattica)
        },
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

# ============================================================================
# DATABASE STRATEGIE DI MITIGAZIONE
# ============================================================================

"""
Ogni mitigazione rappresenta un'azione di risposta a un incidente
In un SOC reale, queste sarebbero le azioni del playbook di incident response
"""

MITIGATION_OPTIONS = {
    'block_ip': {'text': 'Block IP address at firewall level', 'icon': '🔒'},
    'implement_mfa': {'text': 'Implement Multi-Factor Authentication', 'icon': '🔐'},
    'isolate_host': {'text': 'Isolate infected host from network', 'icon': '🚫'},
    'forensic_analysis': {'text': 'Perform forensic analysis and memory dump', 'icon': '🔍'},
    'remove_persistence': {'text': 'Remove persistence mechanisms', 'icon': '🗑️'},
    'block_c2': {'text': 'Block C2 communication channels', 'icon': '⛔'}
}

# ============================================================================
# GESTIONE SESSIONI UTENTE
# ============================================================================

"""
Dizionario per memorizzare le sessioni attive
Struttura: {session_id: {dati_sessione}}
"""
user_sessions = {}

# ============================================================================
# FUNZIONI HELPER
# ============================================================================

def calculate_difficulty(score, streak, accuracy):
    """
    Calcola il livello di difficoltà appropriato basandosi sulle performance
    
    Args:
        score (int): Punteggio totale del giocatore
        streak (int): Serie di risposte corrette consecutive
        accuracy (float): Percentuale di accuratezza (0-100)
    
    Returns:
        str: 'easy', 'medium', o 'hard'
    
    Logica:
        - Formula pesata che combina tre metriche
        - Score contribuisce 30%, streak aggiunge punti fissi, accuracy 40%
        - Soglie predefinite determinano il livello
    """
    # Calcolo del punteggio di performance complessivo
    performance_score = (score * 0.3) + (streak * 10) + (accuracy * 0.4)
    
    # Determinazione del livello basata su soglie
    if performance_score < 50:
        return 'easy'                   # Principiante: necessita log più semplici
    elif performance_score < 150:
        return 'medium'                 # Intermedio: può gestire complessità moderata
    else:
        return 'hard'                   # Esperto: pronto per sfide avanzate

# ============================================================================
# ENDPOINTS API REST
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """
    Endpoint di health check per verificare che il server sia attivo
    
    Returns:
        JSON con status e timestamp
    
    Utilizzato per:
        - Monitoring del servizio
        - Verifiche di connettività dal frontend
    """
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

@app.route('/api/get-log', methods=['POST'])
def get_log():
    """
    Endpoint principale per ottenere un nuovo log da analizzare
    
    Request Body:
        - difficulty: livello di difficoltà richiesto
        - session_id: identificatore della sessione
        - stats: statistiche correnti del giocatore
    
    Returns:
        JSON con:
        - log: evento di sicurezza da analizzare (senza risposte corrette)
        - mitre_options: lista di tecniche MITRE tra cui scegliere
        - mitigation_options: lista di mitigazioni disponibili
        - time_limit: tempo disponibile in secondi
    
    Processo:
        1. Riceve difficoltà e statistiche
        2. Seleziona un log casuale appropriato
        3. Mescola le opzioni per rendere più difficile
        4. Salva la risposta corretta in sessione
        5. Ritorna i dati senza le soluzioni
    """
    # Estrazione dati dalla richiesta
    data = request.json
    difficulty = data.get('difficulty', 'easy')
    session_id = data.get('session_id', 'default')
    
    # STEP 1: Selezione casuale di un log per la difficoltà richiesta
    logs = LOGS_DATABASE.get(difficulty, LOGS_DATABASE['easy'])
    log = random.choice(logs) 
    
    # STEP 2: Preparazione opzioni MITRE (mescolate per difficoltà)
    mitre_options = MITRE_OPTIONS.get(difficulty, MITRE_OPTIONS['easy']).copy()
    random.shuffle(mitre_options) # Mescola per evitare pattern prevedibili
    
    # STEP 3: Salvataggio risposte corrette in sessione (server-side)
    # Questo previene cheating - le risposte non sono mai inviate al client
    if session_id not in user_sessions:
        user_sessions[session_id] = {}
    
    user_sessions[session_id]['current_log'] = log['id']
    user_sessions[session_id]['correct_mitre'] = log['correctMitre']
    user_sessions[session_id]['correct_mitigation'] = log['correctMitigation']
    
    # STEP 4: Preparazione risposta (senza soluzioni)
    response_log = {
        'id': log['id'],
        'raw': log['raw'],
        'source': log['source'],
        'severity': log['severity'],
        'timestamp': log['timestamp'],
        'metadata': log['metadata']
        # NOTA: correctMitre e correctMitigation NON sono inclusi
    }
    
    return jsonify({
        'log': response_log,
        'mitre_options': mitre_options,
        'mitigation_options': list(MITIGATION_OPTIONS.keys())[:4],
        'time_limit': 60 if difficulty == 'easy' else 45 if difficulty == 'medium' else 30
    })

@app.route('/api/validate', methods=['POST'])
def validate_answer():
    """
    Endpoint per validare la risposta dell'utente
    
    Request Body:
        - session_id: identificatore sessione
        - selected_mitre: tecnica MITRE selezionata dall'utente
        - selected_mitigation: mitigazione selezionata
        - time_remaining: secondi rimasti quando ha risposto
        - difficulty: livello di difficoltà corrente
    
    Returns:
        JSON con:
        - is_correct: se la risposta completa è corretta
        - is_mitre_correct: se la tecnica MITRE è corretta
        - is_mitigation_correct: se la mitigazione è corretta
        - correct_mitre: la risposta corretta MITRE
        - correct_mitigation: la mitigazione corretta
        - points: punti guadagnati
        - explanation: spiegazione educativa
    
    Sistema di punteggio:
        - Punti base per difficoltà (easy:10, medium:25, hard:50)
        - Bonus tempo: 0.5 punti per secondo rimanente
        - 0 punti se sbagliato o tempo scaduto
    """
    # Estrazione dati dalla richiesta
    data = request.json
    session_id = data.get('session_id', 'default')
    selected_mitre = data.get('selected_mitre')
    selected_mitigation = data.get('selected_mitigation')
    time_remaining = data.get('time_remaining', 0)
    difficulty = data.get('difficulty', 'easy')
    
    # STEP 1: Recupero risposte corrette dalla sessione
    session = user_sessions.get(session_id, {})
    correct_mitre = session.get('correct_mitre')
    correct_mitigation = session.get('correct_mitigation')
    
    # STEP 2: Validazione delle risposte
    is_mitre_correct = selected_mitre == correct_mitre
    is_mitigation_correct = selected_mitigation == correct_mitigation
    is_fully_correct = is_mitre_correct and is_mitigation_correct
    
    # STEP 3: Calcolo punti
    points = 0
    if is_fully_correct:
        # Punti base per difficoltà
        base_points = {'easy': 10, 'medium': 25, 'hard': 50}
        # Bonus velocità: premia risposte rapide
        time_bonus = int(time_remaining * 0.5)
        points = base_points.get(difficulty, 10) + time_bonus
    
    # STEP 4: Recupero spiegazione educativa
    log_id = session.get('current_log')
    explanation = None

    # Cerca il log nel database per ottenere la spiegazione
    for diff_level in LOGS_DATABASE.values():
        for log in diff_level:
            if log['id'] == log_id:
                explanation = log.get('explanation', 'Analysis complete.')
                break
    
    # STEP 6: Ritorno risultati completi per feedback
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
    """
    Endpoint per calcolare la difficoltà adattiva
    
    Request Body:
        - score: punteggio corrente
        - streak: serie di risposte corrette
        - accuracy: percentuale di accuratezza
    
    Returns:
        JSON con:
        - next_difficulty: prossimo livello suggerito
        - reasoning: spiegazione del calcolo
    
    Utilizzato per:
        - Adattamento dinamico della difficoltà
        - Personalizzazione dell'esperienza di apprendimento
    """
    data = request.json
    score = data.get('score', 0)
    streak = data.get('streak', 0)
    accuracy = data.get('accuracy', 100)
    
    # Usa la funzione helper per calcolare
    next_difficulty = calculate_difficulty(score, streak, accuracy)
    
    return jsonify({
        'next_difficulty': next_difficulty,
        'reasoning': f'Based on score: {score}, streak: {streak}, accuracy: {accuracy}%'
    })

@app.route('/api/leaderboard', methods=['GET'])
def get_leaderboard():
    """
    Endpoint per ottenere la classifica dei migliori giocatori
    
    Returns:
        JSON con lista dei top player
    
    Note:
        - Attualmente ritorna dati mock
        - In produzione si collegherebbe a un database
    """
    # Mock data per dimostrazione
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
    """
    Endpoint per ottenere statistiche dettagliate dell'utente
    
    Request Body:
        - session_id: identificatore sessione
    
    Returns:
        JSON con statistiche complete del giocatore
    
    Utilizzato per:
        - Dashboard personale
        - Tracking progressi
        - Achievements
    """
    data = request.json
    session_id = data.get('session_id', 'default')
    
     # Mock statistics - in produzione verrebbero dal database
    stats = {
        'total_games': 15,
        'total_score': 850,
        'best_streak': 7,
        'average_accuracy': 85.5,
        'favorite_difficulty': 'medium',
        'achievements': [
            'First Log',       # Prima analisi completata
            'Streak Master',   # 5+ risposte corrette di fila
            'Quick Analyzer'   # Risposta in meno di 10 secondi
        ]
    }
    
    return jsonify(stats)

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    """
    Avvia il server Flask in modalità debug
    
    Configurazioni:
        - debug=True: ricarica automatica quando il codice cambia
        - port=5000: porta standard Flask
    
    In produzione:
        - Usare un WSGI server come Gunicorn
        - Disabilitare debug mode
        - Configurare HTTPS
    """
    app.run(debug=True, port=5000)