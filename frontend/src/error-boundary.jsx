import { Component } from 'react';

/**
 * Recovers the localhost console when a browser extension mutates the DOM
 * mid-render (classic React insertBefore NotFoundError → white screen).
 */
export class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { failed: false };
  }

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(error, info) {
    console.error('Privacy console render failure', error, info?.componentStack);
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div className="fatal-recovery" role="alert">
        <h1>Console interrupted</h1>
        <p>
          The UI stopped after a DOM conflict (often a browser extension). Your gateway
          API is unaffected — recover the console without losing the page session.
        </p>
        <div className="fatal-actions">
          <button type="button" onClick={() => this.setState({ failed: false })}>
            Restore console
          </button>
          <button type="button" className="fatal-secondary" onClick={() => window.location.reload()}>
            Reload page
          </button>
        </div>
      </div>
    );
  }
}
