import React, { createContext, useContext, useState, useEffect } from 'react';
import { jwtDecode } from 'jwt-decode';

const AuthContext = createContext();

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));

  useEffect(() => {
    const handleTokenChange = () => {
      const currentToken = localStorage.getItem('token');
      if (currentToken) {
        try {
          const decoded = jwtDecode(currentToken);
          setUser({ id: decoded.id, username: decoded.username });
          setToken(currentToken);
        } catch (err) {
          logout();
        }
      } else {
        setUser(null);
        setToken(null);
      }
    };

    // Run on initial mount and whenever token state changes
    handleTokenChange();

    // Listen for manual changes to localStorage (e.g., pasting token in dev tools)
    window.addEventListener('storage', handleTokenChange);
    
    // Custom event listener for when we change it in the same window via console
    const originalSetItem = localStorage.setItem;
    localStorage.setItem = function(key, value) {
      originalSetItem.apply(this, arguments);
      if (key === 'token') handleTokenChange();
    };

    return () => {
      window.removeEventListener('storage', handleTokenChange);
      localStorage.setItem = originalSetItem;
    };
  }, []);

  const login = (newToken, userData) => {
    localStorage.setItem('token', newToken);
    setToken(newToken);
    setUser(userData);
  };

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, token, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};
