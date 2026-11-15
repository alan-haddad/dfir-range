import { escapeXml } from './lib/encode';
import type { Rng } from './lib/prng';
import { sysTime } from './world';

// Generic Windows event renderer (wevtutil XML and Winlogbeat-style JSON lines)
// for the Security, System and extra Sysmon events used by modules 8 to 13.

export interface WinEvent {
  provider: string;
  providerGuid?: string;
  eventId: number;
  version: number;
  level: number;
  task: number;
  keywords: string;
  channel: string;
  computer: string;
  time: Date;
  data: [string, string][];
  /** System events with EventID qualifiers, e.g. 16384 for Service Control Manager. */
  qualifiers?: number;
}

export const PROVIDERS = {
  sysmon: { provider: 'Microsoft-Windows-Sysmon', providerGuid: '{5770385f-c22a-43e0-bf4c-06f5698ffbd9}', channel: 'Microsoft-Windows-Sysmon/Operational', keywords: '0x8000000000000000', level: 4 },
  security: { provider: 'Microsoft-Windows-Security-Auditing', providerGuid: '{54849625-5478-4994-a5ba-3e3b0328c30d}', channel: 'Security', keywords: '0x8020000000000000', level: 0 },
  scm: { provider: 'Service Control Manager', providerGuid: '{555908d1-a6d7-4695-8e1e-26931d2012f4}', channel: 'System', keywords: '0x8080000000000000', level: 4 },
};

export function eventsXml(events: WinEvent[], rng: Rng, firstRecord: number): string {
  const out = ['<?xml version="1.0" encoding="utf-8"?>', '<Events>'];
  events.forEach((e, i) => {
    out.push('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">');
    out.push('  <System>');
    out.push(`    <Provider Name="${escapeXml(e.provider)}"${e.providerGuid ? ` Guid="${e.providerGuid}"` : ''}${e.provider === 'Service Control Manager' ? ' EventSourceName="Service Control Manager"' : ''} />`);
    out.push(e.qualifiers !== undefined ? `    <EventID Qualifiers="${e.qualifiers}">${e.eventId}</EventID>` : `    <EventID>${e.eventId}</EventID>`);
    out.push(`    <Version>${e.version}</Version>`);
    out.push(`    <Level>${e.level}</Level>`);
    out.push(`    <Task>${e.task}</Task>`);
    out.push('    <Opcode>0</Opcode>');
    out.push(`    <Keywords>${e.keywords}</Keywords>`);
    out.push(`    <TimeCreated SystemTime="${sysTime(e.time, rng)}" />`);
    out.push(`    <EventRecordID>${firstRecord + i}</EventRecordID>`);
    out.push('    <Correlation />');
    out.push(`    <Execution ProcessID="${rng.int(500, 1200)}" ThreadID="${rng.int(1000, 9999)}" />`);
    out.push(`    <Channel>${escapeXml(e.channel)}</Channel>`);
    out.push(`    <Computer>${escapeXml(e.computer)}</Computer>`);
    out.push(e.channel === 'Security' ? '    <Security />' : '    <Security UserID="S-1-5-18" />');
    out.push('  </System>');
    out.push('  <EventData>');
    for (const [k, v] of e.data) out.push(`    <Data Name="${k}">${escapeXml(v)}</Data>`);
    out.push('  </EventData>');
    out.push('</Event>');
  });
  out.push('</Events>', '');
  return out.join('\r\n');
}

export function eventsJsonl(events: WinEvent[], firstRecord: number): string {
  return (
    events
      .map((e, i) =>
        JSON.stringify({
          '@timestamp': e.time.toISOString(),
          event: { code: String(e.eventId), provider: e.provider, kind: 'event' },
          host: { name: e.computer },
          winlog: {
            channel: e.channel,
            provider_name: e.provider,
            event_id: e.eventId,
            record_id: firstRecord + i,
            computer_name: e.computer,
            event_data: Object.fromEntries(e.data),
          },
        }),
      )
      .join('\n') + '\n'
  );
}

export function hex(n: number): string {
  return `0x${n.toString(16)}`;
}
