// test stand-in for the device link
const approvals = new Map<string, { approved: boolean }>();
export const device = {
  async call(method: string, params: any): Promise<any> {
    if (method === 'totp.begin') { approvals.set('ap1', { approved: process.env.FAKE_DENY ? false : true }); return { status: 'pending', approvalId: 'ap1' }; }
    if (method === 'totp.collect') return approvals.get(params.approvalId)?.approved ? { status: 'approved', code: '492 017', secondsLeft: 21 } : { status: 'denied' };
    return { status: 'cancelled' };
  },
};
