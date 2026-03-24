public class ServerInterceptor {
    public ServerInterceptor() {
        System.out.println("[Server] MITM relay mode (ROT13 decode)");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {
        String clear = rot13(message);

        System.out.println("[MITM] Intercepted message from client " + fromClient +
                " to client " + toClient);
        System.out.println("[MITM] Ciphertext seen by server: " + message);
        System.out.println("[MITM] Decrypted cleartext: " + clear);

        return message; // on relaie sans modifier
    }

    private String rot13(String text) {
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (c >= 'a' && c <= 'z') {
                result.append((char) ((c - 'a' + 13) % 26 + 'a'));
            } else if (c >= 'A' && c <= 'Z') {
                result.append((char) ((c - 'A' + 13) % 26 + 'A'));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
}