(function() {
    const API_URL = "https://ticket-0kzh.onrender.com/api";
    
    // 1. Inject CSS
    const style = document.createElement('style');
    style.innerHTML = `
        #ticket-widget-btn { position: fixed; bottom: 20px; right: 20px; z-index: 9999; padding: 15px; background: #007bff; color: white; border: none; border-radius: 50px; cursor: pointer; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        #ticket-container { position: fixed; bottom: 80px; right: 20px; width: 350px; height: 500px; background: white; border: 1px solid #ccc; border-radius: 10px; z-index: 9999; display: none; box-shadow: 0 5px 15px rgba(0,0,0,0.2); flex-direction: column; }
        #ticket-header { background: #007bff; color: white; padding: 10px; border-radius: 10px 10px 0 0; font-weight: bold; display: flex; justify-content: space-between; }
        #ticket-body { flex: 1; padding: 10px; overflow-y: auto; background: #f9f9f9; }
        .msg { margin-bottom: 10px; padding: 8px; border-radius: 5px; max-width: 80%; }
        .msg.user { background: #007bff; color: white; align-self: flex-end; margin-left: auto; }
        .msg.admin { background: #e9ecef; color: black; align-self: flex-start; }
        #ticket-footer { padding: 10px; border-top: 1px solid #eee; display: flex; }
        #ticket-input { flex: 1; padding: 5px; }
        .form-group { margin-bottom: 10px; }
        .form-group input, .form-group textarea { width: 100%; padding: 5px; margin-top: 5px; }
    `;
    document.head.appendChild(style);

    // 2. Create UI Elements
    const btn = document.createElement('button');
    btn.id = 'ticket-widget-btn';
    btn.innerText = 'Support';
    document.body.appendChild(btn);

    const container = document.createElement('div');
    container.id = 'ticket-container';
    container.innerHTML = `
        <div id="ticket-header"><span>Support Chat</span> <span id="close-chat" style="cursor:pointer;">x</span></div>
        <div id="ticket-body"></div>
        <div id="ticket-footer" style="display:none;">
            <input type="text" id="chat-input" placeholder="Type a reply...">
            <button id="send-reply">Send</button>
        </div>
    `;
    document.body.appendChild(container);

    // 3. Logic
    const body = document.getElementById('ticket-body');
    const footer = document.getElementById('ticket-footer');
    
    // Toggle Window
    btn.onclick = () => { container.style.display = container.style.display === 'none' ? 'flex' : 'none'; checkState(); };
    document.getElementById('close-chat').onclick = () => container.style.display = 'none';

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
        body.innerHTML = `
            <div class="form-group"><label>Name</label><input type="text" id="t-name"></div>
            <div class="form-group"><label>Email</label><input type="email" id="t-email"></div>
            <div class="form-group"><label>Account (10 digits)</label><input type="text" id="t-account"></div>
            <div class="form-group"><label>Description</label><textarea id="t-desc"></textarea></div>
            <button id="submit-ticket" style="width:100%; background:#28a745; color:white; border:none; padding:10px;">Start Chat</button>
        `;
        document.getElementById('submit-ticket').onclick = submitTicket;
    }

    async function submitTicket() {
        const data = {
            name: document.getElementById('t-name').value,
            email: document.getElementById('t-email').value,
            account: document.getElementById('t-account').value,
            description: document.getElementById('t-desc').value
        };

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
            alert('Error: ' + result.message);
        }
    }

    let chatInterval;

    function showChat(ticketId) {
        footer.style.display = 'flex';
        // Poll for messages every 3 seconds
        loadMessages(ticketId);
        if (chatInterval) clearInterval(chatInterval);
        chatInterval = setInterval(() => loadMessages(ticketId), 3000);

        document.getElementById('send-reply').onclick = () => sendReply(ticketId);
    }

    async function loadMessages(ticketId) {
        const res = await fetch(`${API_URL}/ticket/${ticketId}/history`);
        const messages = await res.json();
        
        body.innerHTML = messages.map(msg => 
            `<div class="msg ${msg.sender_type}">${msg.content}</div>`
        ).join('');
        body.scrollTop = body.scrollHeight; // Auto scroll to bottom
    }

    async function sendReply(ticketId) {
        const input = document.getElementById('chat-input');
        if (!input.value) return;

        await fetch(`${API_URL}/reply`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                ticket_id: ticketId,
                sender_type: 'user',
                message: input.value
            })
        });
        input.value = '';
        loadMessages(ticketId); // Refresh immediately
    }
})();