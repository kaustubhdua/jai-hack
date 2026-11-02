import { Activity, Cpu, Waves } from "lucide-react";

type InferenceLoaderProps = {
  title: string;
  detail?: string;
  compact?: boolean;
};

/** An honest indeterminate state: the API owns inference progress, so the UI never invents percentages or completed agent stages. */
export function InferenceLoader({ title, detail, compact = false }: InferenceLoaderProps) {
  return (
    <div className={"inference-loader" + (compact ? " inference-loader-compact" : "")} role="status" aria-live="polite" aria-atomic="true">
      <div className="inference-loader-orbit" aria-hidden="true">
        <span className="inference-orbit-ring" />
        <span className="inference-orbit-core"><Cpu size={compact ? 15 : 18} /></span>
        <span className="inference-orbit-signal"><Activity size={compact ? 10 : 12} /></span>
      </div>
      <div className="inference-loader-copy">
        <strong>{title}</strong>
        <span>{detail ?? "The model is processing the request. This can take a few seconds."}</span>
        <span className="inference-loader-track" aria-hidden="true"><i /></span>
      </div>
      <div className="inference-loader-wave" aria-hidden="true"><Waves size={compact ? 15 : 18} /></div>
    </div>
  );
}

/** Avoid a one-frame flash for fast responses without adding a long artificial wait. */
export async function holdLoaderForMinimum(startedAt: number, minimumMs = 650): Promise<void> {
  const remaining = minimumMs - (Date.now() - startedAt);
  if (remaining > 0) await new Promise<void>(resolve => window.setTimeout(resolve, remaining));
}
