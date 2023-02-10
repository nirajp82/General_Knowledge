# TCP

Useful Article Link
https://www.khanacademy.org/computing/computers-and-internet/xcae6f4a7ff015e7d:the-internet/xcae6f4a7ff015e7d:transporting-packets/a/transmission-control-protocol--tcp

## Here's a step-by-step explanation of the TCP connection termination process:
In a Transmission Control Protocol (TCP) connection, the FIN (Finish) flag is used to indicate that a party wants to close the connection. The process of closing a TCP connection is called the TCP Connection Termination, and it involves a series of steps that both the sender and receiver follow to gracefully close the connection.

Closing the sending side: The first step in closing a TCP connection is initiated by the sender, who sets the FIN flag in the TCP header of a packet to indicate that it has no more data to send. The FIN packet is then sent to the receiver.

Reception of FIN by the receiver: When the receiver receives the FIN packet, it sends an acknowledgment (ACK) to the sender, indicating that it has received the FIN. The receiver then stops accepting new data from the sender and enters a TIME_WAIT state.

Last ACK from the receiver: After entering the TIME_WAIT state, the receiver waits for a specified amount of time to ensure that any remaining packets in the network have been delivered. If the receiver does not receive any more data from the sender during this time, it sends a final ACK to the sender to acknowledge the receipt of the FIN.

Closing the receiving side: After receiving the final ACK from the receiver, the sender can close its end of the connection.

End of the connection: After both sides have closed their ends of the connection, the TCP connection is terminated.
