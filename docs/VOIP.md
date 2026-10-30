# Phone calls for critical alerts

Only `alert`-level events (e.g. a canary file opened, a serious intrusion signal) can ring a phone. Everything else is a message. Pick one driver in `rmon setup` (`notify.call.driver`):

## twilio

You need a Twilio account, a voice-enabled number and the auth token. Answers: account SID, your Twilio number, the number to call; the token goes to `secrets.json` (`twilio_token`). RMON posts a call with a short spoken message (`<Say>`), French or English depending on `branding.lang`.

## asterisk (your own SIP / VoIP PBX)

For anyone who runs Asterisk/FreePBX with a SIP trunk or a desk phone. `notify.call.to` is the extension or number, `notify.call.asterisk.endpoint` the channel technology (e.g. `PJSIP`). RMON sets the global variable `RMON_MESSAGE` and originates a call into the context `rmon-alert` (extension `s`). Add this dialplan (adapt the voice engine to what you have installed: Festival, Piper, Google/AWS TTS, or just a recorded prompt):

```
[rmon-alert]
exten => s,1,Answer()
 same => n,Wait(1)
 same => n,Playback(beep)
 same => n,Festival(${RMON_MESSAGE})      ; or: System(piper ...) + Playback(), or Playback(your-prompt)
 same => n,Wait(1)
 same => n,Hangup()
```

The user running `rmon-guard` must be allowed to run `asterisk -rx` (it is root by default).

## command (anything else)

`notify.call.command` is split like a shell line but run **without a shell**; `{message}` and `{to}` are substituted as single arguments, so a hostile message cannot inject commands:

```json
"call": {"driver": "command", "to": "+15550100", "command": "/usr/local/bin/my-caller {to} {message}"}
```

Use it for any provider (OVH, Vonage, Plivo, a SIM modem...).

## Quiet hours

`only_during_quiet_hours: true` rings only between `quiet_hours` (default 22h-8h); during the day an alert is a push/message instead. Test with `sudo rmon notify-test`.
