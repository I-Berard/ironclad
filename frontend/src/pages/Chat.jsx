import React, { useState, useEffect, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import { API_BASE_URL } from '../config';

const Chat = () => {
  const [messages, setMessages] = useState([]);
  const [users, setUsers] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [activeChat, setActiveChat] = useState('global'); // 'global' or user_id
  const [activeChatUser, setActiveChatUser] = useState(null);
  const [showChatArea, setShowChatArea] = useState(false); // For mobile toggle
  const { user, token, logout } = useAuth();
  const messagesEndRef = useRef(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/users`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        if (Array.isArray(data)) {
          setUsers(data.filter(u => u.id !== user.id)); // Exclude self
        }
      } catch (err) {
        console.error('Failed to fetch users');
      }
    };
    fetchUsers();
  }, [token, user.id]);

  const fetchMessages = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/messages?chatWith=${activeChat}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      if (Array.isArray(data)) {
        setMessages(data);
      } else if (data.error) {
        console.error('API Error:', data.error);
      }
    } catch (err) {
      console.error('Failed to fetch messages');
    }
  };

  useEffect(() => {
    fetchMessages();
    const interval = setInterval(fetchMessages, 3000);
    return () => clearInterval(interval);
  }, [activeChat, token]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSend = async (e) => {
    e.preventDefault();
    if (!newMessage.trim()) return;

    try {
      await fetch(`${API_BASE_URL}/api/messages`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ 
          content: newMessage,
          receiver_id: activeChat === 'global' ? null : activeChat
        })
      });
      setNewMessage('');
      fetchMessages();
    } catch (err) {
      console.error('Failed to send message');
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const openChat = (id, userObj = null) => {
    setActiveChat(id);
    setActiveChatUser(userObj);
    setShowChatArea(true);
  };

  return (
    <div className={`dashboard ${showChatArea ? 'show-chat' : ''}`}>
      {/* SIDEBAR: Messages List */}
      <div className="sidebar">
        <div className="top-header">
          <div className="header-top-row">
            <button className="back-btn" style={{visibility: 'hidden'}}>&#8592;</button>
            <span className="header-title">MESSAGES</span>
            <div className="avatar" onClick={() => navigate(`/profile/${user.username}`)} style={{cursor: 'pointer'}}>
              {user.username.charAt(0).toUpperCase()}
            </div>
          </div>
          <p style={{fontSize: '0.8rem', opacity: 0.8, marginTop: '1rem'}}>
            <Link to={`/profile/${user.username}`} style={{color: 'white'}}>Edit Profile</Link> | 
            <a href="#" onClick={handleLogout} style={{color: 'white', marginLeft: '5px'}}>Logout</a>
          </p>
        </div>
        
        <div className="user-list">
          <div 
            className={`user-item ${activeChat === 'global' ? 'active' : ''}`}
            onClick={() => openChat('global')}
          >
            <div className="avatar" style={{background: 'linear-gradient(135deg, #60a5fa, #c084fc)'}}>G</div>
            <div className="user-info">
              <div className="user-name">Global Chat</div>
              <div className="user-snippet">Public room for everyone</div>
            </div>
          </div>
          
          <div style={{margin: '1rem 0', fontWeight: 500, color: 'var(--text-gray)', padding: '0 1rem'}}>Direct Messages</div>
          
          {users.map((u) => (
            <div 
              key={u.id}
              className={`user-item ${activeChat === u.id ? 'active' : ''}`}
              onClick={() => openChat(u.id, u)}
            >
              <div className="avatar">{u.username.charAt(0).toUpperCase()}</div>
              <div className="user-info">
                <div className="user-name">{u.username}</div>
                {/* INTENTIONAL STORED XSS: Bio can execute script here if previewed, though we render it safely here to focus XSS on chat/profile */}
                <div className="user-snippet">{u.bio ? u.bio.replace(/<[^>]*>?/gm, '') : 'Say hi!'}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* CHAT AREA */}
      <div className="chat-area">
        <div className="top-header chat-header">
          <button className="back-btn" onClick={() => setShowChatArea(false)}>&#8592;</button>
          <div className="avatar" style={activeChat === 'global' ? {background: 'linear-gradient(135deg, #60a5fa, #c084fc)'} : {}}>
            {activeChat === 'global' ? 'G' : (activeChatUser?.username.charAt(0).toUpperCase())}
          </div>
          <div style={{flex: 1}}>
            <div className="header-title">{activeChat === 'global' ? 'Global Chat' : activeChatUser?.username}</div>
            <div style={{fontSize: '0.75rem', opacity: 0.8}}>Online</div>
          </div>
        </div>

        <div className="messages-container">
          {messages.length === 0 && (
            <div style={{textAlign: 'center', color: 'var(--text-gray)', marginTop: '2rem'}}>No messages yet.</div>
          )}
          {Array.isArray(messages) && messages.map((msg) => {
            const isSentByMe = msg.username === user.username;
            return (
              <div key={msg.id} className={`message-wrapper ${isSentByMe ? 'sent' : 'received'}`}>
                <div className="message-sender">
                  <Link to={`/profile/${msg.username}`} style={{color: 'inherit', textDecoration: 'none'}}>{msg.username}</Link>
                </div>
                <div className="message-bubble" dangerouslySetInnerHTML={{ __html: msg.content }} />
                <div className="message-time">
                  {new Date(msg.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                </div>
              </div>
            );
          })}
          <div ref={messagesEndRef} />
        </div>

        <div className="input-area">
          <form className="input-container" onSubmit={handleSend}>
            <span style={{padding: '0 0.5rem', color: '#94a3b8', cursor: 'pointer'}}>📷</span>
            <input 
              type="text" 
              placeholder="Type Your Message" 
              value={newMessage}
              onChange={(e) => setNewMessage(e.target.value)}
            />
            <button type="submit" className="send-btn">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="22" y1="2" x2="11" y2="13"></line>
                <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
              </svg>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Chat;
