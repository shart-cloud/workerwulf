export function issueChallenge() {
  const challenge: Record<string, number> = {};
  // ruleid: wulf-insecure-random
  challenge.nonce = Math.random();
  return challenge;
}
