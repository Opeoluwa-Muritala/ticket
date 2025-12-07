(function() {
    'use strict';

    // 1. HTTPS Enforced
    const API_URL = "https://ticket-0kzh.onrender.com/api";
    let chatInterval = null;

    // 2. Inject CSS
    const style = document.createElement('style');
    style.innerHTML = `
        #ticket-widget-btn { position: fixed; bottom: 20px; right: 20px; z-index: 9999; padding: 15px; background: #007bff; color: white; border: none; border-radius: 50px; cursor: pointer; box-shadow: 0 4px 6px rgba(0,0,0,0.1); font-family: sans-serif; transition: transform 0.2s; }
        #ticket-widget-btn:hover { transform: scale(1.05); }
        #ticket-container { position: fixed; bottom: 80px; right: 20px; width: 350px; height: 500px; background: white; border: 1px solid #ccc; border-radius: 10px; z-index: 9999; display: none; box-shadow: 0 5px 15px rgba(0,0,0,0.2); flex-direction: column; font-family: sans-serif; }
        #ticket-header { background:rgb(255, 0, 221); color: white; padding: 15px; border-radius: 10px 10px 0 0; font-weight: bold; display: flex; justify-content: space-between; align-items: center; }
        #ticket-body { flex: 1; padding: 15px; overflow-y: auto; background: #f9f9f9; display: flex; flex-direction: column; gap: 10px; }
        .msg { padding: 10px; border-radius: 8px; max-width: 80%; word-wrap: break-word; font-size: 14px; line-height: 1.4; }
        .msg.user { background: #007bff; color: white; align-self: flex-end; }
        .msg.admin { background: #e9ecef; color: #333; align-self: flex-start; }
        #ticket-footer { padding: 15px; border-top: 1px solid #eee; display: flex; gap: 10px; background: #fff; border-radius: 0 0 10px 10px; }
        #chat-input { flex: 1; padding: 8px; border: 1px solid #ccc; border-radius: 4px; outline: none; }
        #chat-input:focus { border-color: #007bff; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: 500; font-size: 14px; }
        .form-group input, .form-group textarea { width: 100%; padding: 8px; margin-top: 5px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        .btn-submit { width: 100%; background: #28a745; color: white; border: none; padding: 10px; border-radius: 4px; cursor: pointer; font-weight: bold; }
        .btn-submit:hover { background: #218838; }
        #close-chat { cursor: pointer; font-size: 1.2em; padding: 0 5px; }
        .error-text { color: red; font-size: 12px; margin-bottom: 10px; display: none; }
    `;
    document.head.appendChild(style);

    // 3. Create UI Elements
    const btn = document.createElement('button');
    btn.id = 'ticket-widget-btn';
    btn.innerText = 'Support';
    btn.setAttribute('aria-label', 'Open Support Chat');
    document.body.appendChild(btn);

    const container = document.createElement('div');
    container.id = 'ticket-container';
    container.setAttribute('role', 'dialog');
    container.setAttribute('aria-modal', 'true');
    container.innerHTML = `
        <div id="ticket-header">
            <span>Support Chat</span> 
            <span id="close-chat" role="button" tabindex="0" aria-label="Close Chat">x</span>
        </div>
        <div id="ticket-body"></div>
        <div id="ticket-footer" style="display:none;">
            <input type="text" id="chat-input" placeholder="Type a reply..." aria-label="Type your message">
            <button id="send-reply" style="padding: 8px 15px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;">Send</button>
        </div>
    `;
    document.body.appendChild(container);

    // 4. Logic
    const body = document.getElementById('ticket-body');
    const footer = document.getElementById('ticket-footer');
    const closeBtn = document.getElementById('close-chat');

    // Toggle Window
    btn.onclick = () => {
        const isHidden = container.style.display === 'none' || container.style.display === '';
        container.style.display = isHidden ? 'flex' : 'none';
        if (isHidden) {
            checkState();
        } else {
            stopPolling(); // Fix memory leak
        }
    };

    // Close Handler (Click + Keyboard)
    const handleClose = () => {
        container.style.display = 'none';
        stopPolling(); // Fix memory leak
        btn.focus(); // Return focus to trigger button
    };
    closeBtn.onclick = handleClose;
    closeBtn.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') handleClose(); };

    function stopPolling() {
        if (chatInterval) {
            clearInterval(chatInterval);
            chatInterval = null;
        }
    }

    function checkState() {
        const ticketId = localStorage.getItem('current_ticket_id');
        if (ticketId) {
            showChat(ticketId);
        } else {
            showForm();
        }
    }

    function showForm() {
        footer.style.display = 'none';
        stopPolling();
        body.innerHTML = `
            <div id="form-error" class="error-text"></div>
            <div class="form-group"><label for="t-name">Name</label><input type="text" id="t-name" required></div>
            <div class="form-group"><label for="t-email">Email</label><input type="email" id="t-email" required></div>
            <div class="form-group"><label for="t-account">Account (10 digits)</label><input type="text" id="t-account" maxlength="10" inputmode="numeric" pattern="[0-9]*"></div>
            <div class="form-group"><label for="t-desc">Description</label><textarea id="t-desc" rows="3" required></textarea></div>
            <button id="submit-ticket" class="btn-submit">Start Chat</button>
        `;
        document.getElementById('submit-ticket').onclick = submitTicket;
    }

    async function submitTicket() {
        const errorDiv = document.getElementById('form-error');
        errorDiv.style.display = 'none';

        const name = document.getElementById('t-name').value.trim();
        const email = document.getElementById('t-email').value.trim();
        const account = document.getElementById('t-account').value.trim();
        const desc = document.getElementById('t-desc').value.trim();

        // Input Validation
        if (!name || !email || !desc) {
            errorDiv.innerText = "Please fill in all required fields.";
            errorDiv.style.display = 'block';
            return;
        }
        if (account && !/^\d{10}$/.test(account)) {
            errorDiv.innerText = "Account number must be 10 digits.";
            errorDiv.style.display = 'block';
            return;
        }

        const data = { name, email, account, description: desc };

        try {
            const btn = document.getElementById('submit-ticket');
            btn.disabled = true;
            btn.innerText = "Processing...";

            const res = await fetch(`${API_URL}/init_ticket`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            });
            const result = await res.json();
            
            if (result.status === 'success') {
                localStorage.setItem('current_ticket_id', result.ticket_id);
                showChat(result.ticket_id);
            } else {
                throw new Error(result.message || 'Unknown error');
            }
        } catch (err) {
            errorDiv.innerText = 'Error: ' + err.message;
            errorDiv.style.display = 'block';
            document.getElementById('submit-ticket').disabled = false;
            document.getElementById('submit-ticket').innerText = "Start Chat";
        }
    }

    function showChat(ticketId) {
        footer.style.display = 'flex';
        
        loadMessages(ticketId);
        
        // Clear existing interval before starting new one
        stopPolling();
        chatInterval = setInterval(() => loadMessages(ticketId), 3000);

        const sendBtn = document.getElementById('send-reply');
        const input = document.getElementById('chat-input');
        
        // Remove old listeners to prevent duplicates
        const newSendBtn = sendBtn.cloneNode(true);
        sendBtn.parentNode.replaceChild(newSendBtn, sendBtn);
        
        newSendBtn.onclick = () => sendReply(ticketId);
        
        // Enter key to send
        input.onkeypress = (e) => {
            if (e.key === 'Enter') sendReply(ticketId);
        };
    }

    async function loadMessages(ticketId) {
        try {
            const res = await fetch(`${API_URL}/ticket/${ticketId}/history`);
            if (!res.ok) {
                if(res.status === 404) {
                    // Ticket closed or deleted
                    localStorage.removeItem('current_ticket_id');
                    showForm();
                    return;
                }
                throw new Error('Failed to load');
            }
            const messages = await res.json();
            
            // Only update DOM if content changed (simple check)
            const currentHTML = messages.map(msg => 
                `<div class="msg ${msg.sender_type}">${escapeHtml(msg.content)}</div>`
            ).join('');
            
            if (body.innerHTML !== currentHTML) {
                body.innerHTML = currentHTML;
                body.scrollTop = body.scrollHeight;
            }
        } catch (err) {
            console.error("Polling error:", err);
            // Don't alert on polling errors to avoid spamming the user
        }
    }

    async function sendReply(ticketId) {
        const input = document.getElementById('chat-input');
        const msg = input.value.trim();
        if (!msg) return;

        input.disabled = true;
        
        try {
            await fetch(`${API_URL}/reply`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    ticket_id: ticketId,
                    sender_type: 'user',
                    message: msg
                })
            });
            input.value = '';
            loadMessages(ticketId);
        } catch (err) {
            alert("Failed to send message. Please try again.");
        } finally {
            input.disabled = false;
            input.focus();
        }
    }

    // Helper to prevent XSS in chat
    function escapeHtml(text) {
        if (!text) return text;
        return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
})();