<script lang="ts">
  // An on/off switch with a label and an optional explanation.
  let {
    checked,
    label,
    detail = '',
    disabled = false,
    onchange,
  }: {
    checked: boolean;
    label: string;
    detail?: string;
    disabled?: boolean;
    onchange: (value: boolean) => void;
  } = $props();
</script>

<label class="toggle" class:disabled>
  <span class="text">
    <span class="label">{label}</span>
    {#if detail}<span class="detail">{detail}</span>{/if}
  </span>
  <input
    type="checkbox"
    role="switch"
    {checked}
    {disabled}
    onchange={(e) => onchange((e.currentTarget as HTMLInputElement).checked)}
  />
  <span class="track" aria-hidden="true"><span class="thumb"></span></span>
</label>

<style>
  .toggle {
    position: relative;
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    padding: 10px 0;
    cursor: pointer;
  }
  .toggle + :global(.toggle) {
    border-top: 1px solid rgb(205 230 255 / 0.07);
  }
  .disabled {
    cursor: default;
    opacity: 0.55;
  }
  .text {
    display: grid;
    gap: 2px;
  }
  .label {
    font-weight: 500;
    font-size: 13.5px;
  }
  .detail {
    font-size: 12px;
    color: var(--text-muted);
  }
  input {
    position: absolute;
    opacity: 0;
    width: 1px;
    height: 1px;
  }
  .track {
    flex: none;
    position: relative;
    width: 40px;
    height: 22px;
    margin-top: 1px;
    border-radius: 11px;
    background: rgb(3 10 18 / 0.5);
    border: 1px solid var(--glass-border-strong);
    transition: background 0.2s var(--ease);
  }
  .thumb {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: var(--text-soft);
    transition:
      transform 0.2s var(--ease),
      background 0.2s var(--ease);
  }
  input:checked + .track {
    background: linear-gradient(180deg, var(--mint), var(--mint-deep));
    border-color: transparent;
  }
  input:checked + .track .thumb {
    transform: translateX(18px);
    background: var(--accent-ink);
  }
  input:focus-visible + .track {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
</style>
