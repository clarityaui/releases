/**
 * THE RELEASE CHANNELS, AND WHAT EACH ONE SIGNS.
 *
 * One table, read by the assembler, the validator and the self-test — and the self-test checks it against the channel
 * options of BOTH workflows, so a channel cannot exist in one place and not another. Before this, the signing rule was
 * written out three times (`channel === 'public-beta' && family !== 'linux'` and two neighbours), which is how a third
 * channel would have been half-added.
 *
 *   internal-unsigned  nothing is signed — internal testing only
 *   mac-signed-beta    macOS signed and notarized; Windows and Linux unsigned — a beta before there is a Windows certificate
 *   public-beta        Windows and macOS signed (macOS notarized); Linux is never signed
 */
export const CHANNELS = {
  'internal-unsigned': { signs: () => false },
  'mac-signed-beta': { signs: (family) => family === 'macos' },
  'public-beta': { signs: (family) => family === 'windows' || family === 'macos' }
}

export const isChannel = (channel) => typeof channel === 'string' && Object.prototype.hasOwnProperty.call(CHANNELS, channel)

/** Whether a leg of this family must be signed on this channel. */
export const signedFor = (channel, family) => isChannel(channel) && CHANNELS[channel].signs(family) === true
