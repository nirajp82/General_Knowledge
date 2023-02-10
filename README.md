# TCP

Useful Article Link
https://www.khanacademy.org/computing/computers-and-internet/xcae6f4a7ff015e7d:the-internet/xcae6f4a7ff015e7d:transporting-packets/a/transmission-control-protocol--tcp

## TCP flag
TCP (Transmission Control Protocol) uses flags to control the flow of data between two devices in a network. The flags are included as part of the TCP header, which is added to each data packet that is sent over the network.

There are several different flags that are used in TCP, including:

* SYN (Synchronize): This flag is used to initiate a new TCP connection. When the SYN flag is set in a packet, it indicates that the sender is requesting to start a new connection.

* ACK (Acknowledgment): This flag is used to acknowledge the receipt of data packets. When the ACK flag is set in a packet, it indicates that the receiver has received the data and is sending an acknowledgment back to the sender.

* FIN (Finish): This flag is used to end an existing TCP connection. When the FIN flag is set in a packet, it indicates that the sender is finished sending data and wants to close the connection.

* RST (Reset): This flag is used to reset an existing TCP connection. When the RST flag is set in a packet, it indicates that there has been an error in the connection and that it needs to be reset.

* PSH (Push): This flag is used to push data to the receiving device as soon as possible, rather than waiting for the buffer to fill up. When the PSH flag is set in a packet, it indicates that the sender wants the data to be delivered to the receiver immediately.

* URG (Urgent): This flag is used to indicate that a data packet contains urgent data. When the URG flag is set in a packet, it indicates that the receiver should process this data before other data that may be in its buffer.

These flags are used in combination to control the flow of data between two devices in a TCP connection. For example, when a new connection is established, the SYN flag is set in the first packet, and the ACK flag is set in the second packet. When data is being transmitted, the ACK flag is set in each packet to acknowledge the receipt of the data. When the connection is closed, the FIN flag is set in the last packet.

## Here's a step-by-step explanation of the TCP connection termination process:
In a Transmission Control Protocol (TCP) connection, the FIN (Finish) flag is used to indicate that a party wants to close the connection. The process of closing a TCP connection is called the TCP Connection Termination, and it involves a series of steps that both the sender and receiver follow to gracefully close the connection.

Closing the sending side: The first step in closing a TCP connection is initiated by the sender, who sets the FIN flag in the TCP header of a packet to indicate that it has no more data to send. The FIN packet is then sent to the receiver.

Reception of FIN by the receiver: When the receiver receives the FIN packet, it sends an acknowledgment (ACK) to the sender, indicating that it has received the FIN. The receiver then stops accepting new data from the sender and enters a TIME_WAIT state.

Last ACK from the receiver: After entering the TIME_WAIT state, the receiver waits for a specified amount of time to ensure that any remaining packets in the network have been delivered. If the receiver does not receive any more data from the sender during this time, it sends a final ACK to the sender to acknowledge the receipt of the FIN.

Closing the receiving side: After receiving the final ACK from the receiver, the sender can close its end of the connection.

End of the connection: After both sides have closed their ends of the connection, the TCP connection is terminated.
