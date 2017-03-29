using System;
using System.Text;
using System.Threading.Tasks;

namespace PipeWorksSampleCodeSubmission
{
    /// <summary>
    /// A simple class that collects and encrypts strings, pushing them onto a buffer.
    /// If the buffer becomes too full to add the next set of data, it is "sent" to
    /// the NSA and cleared.
    /// </summary>
    public class NotTheNSA
    {
        #region Member Constants
        private const int BYTEBUFFERSIZE = 128;
        private readonly byte[] SECRETKEY = new byte[8] { 0x00, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x00 };
        #endregion

        #region Member Variables
        private int _CurrentBufferIndex = 0;
        private byte[] _ByteBuffer = new byte[BYTEBUFFERSIZE];
        #endregion

        #region Public Methods
        /// <summary>
        /// Encrypt a message to be sent to the NSA.
        /// </summary>
        /// <param name="message"></param>
        /// <exception cref="Exception">On programmer error.</exception>
        public void CollectInformation(string message)
        {
            byte[] encryptedMessage;

            if (!string.IsNullOrEmpty(message))
            {
                encryptedMessage = EncryptForYourSecurity(message);

                ProcessInformation(encryptedMessage);
            }
        }

        /// <summary>
        /// Flushes the buffer to NSA headquarters.
        /// </summary>
        public void FlushInformation()
        {
            SendBufferAndClear();
        }
        #endregion

        #region Private Methods
        private void ProcessInformation(byte[] encryptedMessage)
        {
            byte[][] segmentedMessage;

            segmentedMessage = SegmentMessageToBufferSize(encryptedMessage);

            foreach(byte[] segment in segmentedMessage)
            {
                if(!AppendToBuffer(segment))
                {
                    SendBufferAndClear();

                    if (!AppendToBuffer(segment))
                    {
                        throw new Exception("Programmer Error: Message segment could not be appended to a clear buffer.");
                    }
                }
            }
        }

        private void SendBufferAndClear()
        {
            byte[] messageToSend = (byte[])_ByteBuffer.Clone();
            Task.Run(() => SendToNSA(messageToSend));

            _ByteBuffer = new byte[BYTEBUFFERSIZE];
            _CurrentBufferIndex = 0;
        }

        private byte[][] SegmentMessageToBufferSize(byte[] encryptedMessage)
        {
            byte[][] segmentedMessage;
            int segments = (encryptedMessage.Length / BYTEBUFFERSIZE) + 1;

            segmentedMessage = new byte[segments][];

            for(int i = 0; i < segments; i++)
            {
                if(encryptedMessage.Length > (i+1) * BYTEBUFFERSIZE) // extract full buffer sized segment
                {
                    segmentedMessage[i] = new byte[BYTEBUFFERSIZE];
                    Array.Copy(encryptedMessage, i * BYTEBUFFERSIZE, segmentedMessage[i], 0, BYTEBUFFERSIZE);
                }
                else // extract leftovers that are smaller than the buffer size
                {
                    int leftoverBytes = encryptedMessage.Length - (i * BYTEBUFFERSIZE);

                    segmentedMessage[i] = new byte[leftoverBytes];
                    Array.Copy(encryptedMessage, i * BYTEBUFFERSIZE, segmentedMessage[i], 0, leftoverBytes);
                }
            }

            return segmentedMessage;
        }

        private bool AppendToBuffer(byte[] encryptedMessage)
        {
            bool success = false;

            if(_CurrentBufferIndex + encryptedMessage.Length <= BYTEBUFFERSIZE)
            {
                // Message fits in current buffer; append it.

                encryptedMessage.CopyTo(_ByteBuffer, _CurrentBufferIndex);

                _CurrentBufferIndex += encryptedMessage.Length;

                success = true;
            }

            return success;
        }

        private byte[] EncryptForYourSecurity(string message)
        {
            int padding;
            byte[] encryptedMessage;

            message = message.Trim();

            encryptedMessage = Encoding.UTF8.GetBytes(message);

            padding = encryptedMessage.Length % SECRETKEY.Length;

            if (padding != 0) // pad to ensure message length is a multiple of key length
            {
                Array.Resize(ref encryptedMessage, encryptedMessage.Length + padding);
            }

            for(int i = 0; i < encryptedMessage.Length; i++) // xor every 8 byte section with key
            {
                encryptedMessage[i] ^= SECRETKEY[i % SECRETKEY.Length];
            }

            // That oughta do it.

            return encryptedMessage;
        } 

        private async Task SendToNSA(byte[] encryptedMessage)
        {
            // Todo: send information to NSA.
            await Task.Delay(30);
        }
        #endregion
    }
}