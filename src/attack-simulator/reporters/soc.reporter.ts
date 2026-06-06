export function generateSocReport(events: any[]) {
  const failed = events.filter(e => e.result?.status >= 400);
  const success = events.filter(e => e.result?.status < 300);

  const suspicious = events.filter(e =>
    e.result?.data?.message?.includes('binding') ||
    e.result?.status === 403,
  );

  return {
    summary: {
      total: events.length,
      success: success.length,
      failed: failed.length,
      suspicious: suspicious.length,
    },

    risk: suspicious.length > 0 ? 'HIGH' : 'LOW',

    timeline: events,
  };
}