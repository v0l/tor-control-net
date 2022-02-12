namespace tor_control_net.Exceptions;

public class TorControlReplyParseException : TorControlException
{
    public TorControlReplyParseException(string message) : base(message)
    {
    }

    public TorControlReplyParseException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
