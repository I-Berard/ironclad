import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import { API_BASE_URL } from '../config';

const Profile = () => {
  const { username } = useParams();
  const { user, token } = useAuth();
  const [profile, setProfile] = useState(null);
  const [editMode, setEditMode] = useState(false);
  const [bioInput, setBioInput] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/profile/${username}`);
        const data = await response.json();
        if (response.ok) {
          setProfile(data);
          setBioInput(data.bio || '');
        } else {
          setError(data.error);
        }
      } catch (err) {
        setError('Failed to fetch profile');
      }
    };
    fetchProfile();
  }, [username]);

  const handleUpdate = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(`${API_BASE_URL}/api/profile`, {
        method: 'PUT',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ bio: bioInput })
      });
      const data = await response.json();
      if (response.ok) {
        setProfile({ ...profile, bio: data.bio });
        setEditMode(false);
      } else {
        setError(data.error);
      }
    } catch (err) {
      setError('Update failed');
    }
  };

  const isOwnProfile = user && profile && user.username === profile.username;

  return (
    <div className="dashboard">
      <div className="chat-area" style={{ display: 'flex', width: '100%' }}>
        <div className="top-header chat-header">
          <button className="back-btn" onClick={() => window.history.back()} style={{ display: 'block' }}>&#8592;</button>
          <div className="header-title">User Profile</div>
          <div style={{ flex: 1, textAlign: 'right' }}>
            <Link to="/" style={{ color: 'white', textDecoration: 'none', fontSize: '0.9rem' }}>Back to Chat</Link>
          </div>
        </div>
        
        <div className="messages-container" style={{ alignItems: 'center', paddingTop: '3rem' }}>
          {error ? (
            <div className="error-text">{error}</div>
          ) : profile ? (
            <div style={{ background: 'var(--bg-card)', padding: '2rem', borderRadius: '30px', width: '100%', maxWidth: '400px', boxShadow: '0 10px 25px rgba(0,0,0,0.05)', border: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem' }}>
                <div className="avatar" style={{ width: '60px', height: '60px', fontSize: '1.5rem' }}>
                  {profile.username.charAt(0).toUpperCase()}
                </div>
                <div>
                  <h3 style={{ color: 'var(--text-dark)', margin: 0 }}>@{profile.username}</h3>
                  <p style={{ color: 'var(--text-gray)', fontSize: '0.85rem', margin: 0 }}>
                    Joined: {new Date(profile.created_at).toLocaleDateString()}
                  </p>
                </div>
              </div>
              
              {!editMode ? (
                <>
                  <div style={{ marginBottom: '0.5rem', fontWeight: 500, color: 'var(--text-dark)' }}>Bio</div>
                  {/* INTENTIONAL STORED XSS VULNERABILITY */}
                  <div 
                    style={{ background: 'var(--bubble-received)', padding: '1rem', borderRadius: '15px', color: 'var(--text-gray)', minHeight: '80px', wordBreak: 'break-word' }}
                    dangerouslySetInnerHTML={{ __html: profile.bio || '<i>No bio set.</i>' }} 
                  />
                  
                  {isOwnProfile && (
                    <button onClick={() => setEditMode(true)} style={{ marginTop: '1.5rem', borderRadius: '15px' }}>
                      Edit Bio
                    </button>
                  )}
                </>
              ) : (
                <form onSubmit={handleUpdate} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <textarea 
                    value={bioInput}
                    onChange={(e) => setBioInput(e.target.value)}
                    style={{
                      width: '100%', 
                      minHeight: '100px', 
                      padding: '1rem', 
                      borderRadius: '15px', 
                      background: 'var(--bubble-received)', 
                      border: '1px solid var(--primary)',
                      outline: 'none',
                      fontFamily: 'inherit',
                      resize: 'vertical'
                    }}
                  />
                  <div style={{ display: 'flex', gap: '10px' }}>
                    <button type="submit" style={{ borderRadius: '15px' }}>Save</button>
                    <button type="button" onClick={() => setEditMode(false)} style={{ background: '#e2e8f0', color: 'var(--text-dark)', borderRadius: '15px' }}>
                      Cancel
                    </button>
                  </div>
                </form>
              )}
            </div>
          ) : (
            <div style={{ color: 'var(--text-gray)' }}>Loading profile...</div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Profile;
