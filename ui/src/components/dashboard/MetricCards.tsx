import { memo } from 'react';
import { Activity, BarChart3, TrendingUp } from 'lucide-react';

type MetricCardProps = { label: string; value: string; highlight?: boolean };
type ModelHealthCardProps = {
  title: string;
  value: number | string;
  color: 'blue' | 'green' | 'amber';
  subtitle?: string;
};

const MetricCardMemo = memo(function MetricCardInner(props: MetricCardProps) {
  return (
    <div
      style={{
        background: props.highlight ? 'rgba(255,255,255,0.10)' : 'rgba(255,255,255,0.05)',
        border: '1px solid rgba(255,255,255,0.10)' + (props.highlight ? ', rgba(255,255,255,0.20)' : ''),
        borderRadius: '1rem',
        padding: '1rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.25rem',
        boxShadow: props.highlight ? '0 20px 25px -5px rgba(0, 0, 0, 0.15)' : 'none',
      }}
    >
      <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.40)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        {props.label}
      </span>
      <span style={{
        fontSize: '1.5rem',
        fontWeight: '700',
        color: props.highlight ? 'white' : 'rgba(255,255,255,0.80)',
      }}>
        {props.value}
      </span>
    </div>
  );
});

const ModelHealthCardMemo = memo(function ModelHealthCardInner(props: ModelHealthCardProps) {
  const style = colorStyles[props.color] ?? colorStyles.blue;

  return (
    <div
      style={{
        background: 'rgba(255,255,255,0.05)',
        border: '1px solid rgba(255,255,255,0.10)',
        borderRadius: '1rem',
        padding: '1rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.5rem',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.40)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          {props.title}
        </span>
        <div style={{ padding: '0.375rem', borderRadius: '0.5rem', background: style.bg }}>
          <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {style.icon}
          </span>
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem' }}>
        <span style={{
          fontSize: '1.5rem',
          fontWeight: '700',
          color: style.color,
        }}>
          {typeof props.value === 'string'
            ? props.value
            : props.value === 0
              ? '0%'
              : props.value <= 1
                ? `${Math.round(props.value * 100)}%`
                : `${props.value}%`}
        </span>
        {typeof props.value === 'number' && props.value > 0 && props.value <= 1 && (
          <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.35)' }}>
            ({props.value.toFixed(2)})
          </span>
        )}
      </div>
    </div>
  );
});

const colorStyles: Record<string, { icon: React.ReactElement; color: string; bg: string }> = {
  blue: {
    icon: <Activity fontSize="16" />,
    color: '#60a5fa',
    bg: 'rgba(96,165,250,0.10)',
  },
  green: {
    icon: <TrendingUp fontSize="16" />,
    color: '#4ade80',
    bg: 'rgba(74,222,128,0.10)',
  },
  amber: {
    icon: <BarChart3 fontSize="16" />,
    color: '#fbbf24',
    bg: 'rgba(251,191,36,0.10)',
  },
};

export { MetricCardMemo as MetricCard, ModelHealthCardMemo as ModelHealthCard };

