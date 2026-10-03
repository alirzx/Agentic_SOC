import { SocFunnelBoardView } from '@/components/funnel/SocFunnelBoardView';

export const metadata = {
  title: 'SOC Funnel | AiSOC',
  description: 'Track alerts from ingest through triage to gated Jira push',
};

export default function SocFunnelPage() {
  return <SocFunnelBoardView />;
}
