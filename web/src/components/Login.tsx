import { useState } from 'react';
import { checkCredentials } from '../auth';
import { setToken } from '../api';

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const host = window.location.host || window.location.hostname;

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const token = checkCredentials(username, password);
    if (!token) {
      setError('Invalid username or password.');
      return;
    }
    setToken(token);
    onLogin();
  }

  return (
    <div className="login-shell">
      <div className="login-info">
        <img src="/zyvor-mark.svg" alt="Zyvor" className="login-logo" />
        <p className="eyebrow">Netra · Zyvor</p>
        <h1>See the network. Diagnose it. Contain it.</h1>
        <p>
          Netra runs its own eBPF datapath for workload flows, TCP health, DNS timing, socket identity, and leased
          emergency controls — a standalone control plane for Kubernetes networking.
        </p>
        <p className="login-host">
          Connecting to <code>{host}</code>
        </p>
      </div>
      <form className="card login-card" onSubmit={submit}>
        <h1>Sign in.</h1>
        <label className="tokenbox">
          Username
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoFocus
            autoComplete="username"
          />
        </label>
        <label className="tokenbox">
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </label>
        {error && <p className="warning">{error}</p>}
        <button type="submit" className="primary">Sign in</button>
      </form>
    </div>
  );
}
