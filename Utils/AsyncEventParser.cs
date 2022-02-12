using tor_control_net.Exceptions;
using tor_control_net.Messages;
using tor_control_net.Messages.Events;
using tor_control_net.Messages.Events.OrEvents;
using tor_control_net.Messages.Events.StatusEvents;

namespace tor_control_net.Utils;

/// <summary>Parses an incoming Tor control event based on its name.</summary>
public static class AsyncEventParser
{
    /// <exception cref="TorControlReplyParseException"/>
    public static IAsyncEvent Parse(TorControlReply reply)
    {
        if (reply.StatusCode != StatusCode.AsynchronousEventNotify)
        {
            throw new TorControlReplyParseException($"Event: Expected {StatusCode.AsynchronousEventNotify} status code.");
        }

        (string value, _) = Tokenizer.ReadUntilSeparator(reply.ResponseLines[0]);

        return value switch
        {
            StatusEvent.EventNameStatusClient or StatusEvent.EventNameStatusServer or StatusEvent.EventNameStatusGeneral => StatusEvent
                .FromReply(reply),
            CircEvent.EventName => CircEvent.FromReply(reply),
            NetworkLivenessEvent.EventName => NetworkLivenessEvent.FromReply(reply),
            OrConnEvent.EventName => OrConnEvent.FromReply(reply),
            _ => throw new NotSupportedException("This should never happen."),
        };
    }
}
