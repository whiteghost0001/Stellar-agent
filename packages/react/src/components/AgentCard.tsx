'use client';

import React from 'react';
import type { Agent } from 'marc-stellar-sdk';

export interface AgentCardProps {
  agent: Agent;
  onHire?: (agent: Agent) => void;
  className?: string;
  style?: React.CSSProperties;
}

export function AgentCard({ agent, onHire, className, style }: AgentCardProps): React.ReactElement {
  return (
    <div
      className={className}
      style={{
        border: '1px solid rgba(0,0,0,0.12)',
        borderRadius: '0.5rem',
        padding: '1rem',
        background: '#ffffff',
        color: '#111827',
        ...style,
      }}
    >
      <div style={{ fontWeight: 600, fontSize: '1.125rem', marginBottom: '0.5rem' }}>
        Agent #{agent.id.toString()}
      </div>
      <div style={{ fontSize: '0.875rem', color: '#4b5563', marginBottom: '0.25rem' }}>
        Owner: {agent.owner}
      </div>
      <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.75rem' }}>
        Metadata: {agent.uri}
      </div>
      {onHire ? (
        <button
          type="button"
          onClick={() => onHire(agent)}
          style={{
            background: '#3b82f6',
            color: '#ffffff',
            border: 'none',
            borderRadius: '0.375rem',
            padding: '0.375rem 0.75rem',
            cursor: 'pointer',
            fontSize: '0.875rem',
            fontWeight: 500,
          }}
        >
          Hire Agent
        </button>
      ) : null}
    </div>
  );
}

export default AgentCard;
