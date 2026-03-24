public class ServerInterceptor {
    public ServerInterceptor() {
        System.out.println("[Server] MITM relay mode (ROT13 decode)");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {
    System.out.println("[MITM] Intercepted message from client " + fromClient +
            " to client " + toClient);
    System.out.println("[MITM] Original ciphertext: " + message);

    // Attaque : on modifie le message
    char[] chars = message.toCharArray();

    if (chars.length > 5) {
        chars[5] = chars[5] == 'A' ? 'B' : 'A'; // flip un caractère
    }

    String modified = new String(chars);

    System.out.println("[MITM] Modified ciphertext: " + modified);

    return modified;
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