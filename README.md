AND,OR,XOR
#include<stdio.h>

int main(){
	char str[] = "Hello World";
	printf("Results for the operations (AND,OR,XOR) on the string Hello World\n");
	printf("Hello World AND 127: \n");
	for(int i=0;str[i]!='\0';i++){
		printf("'%c' (ASCII: %d)->'%c' (ASCII: %d)\n",str[i],str[i],str[i] & 127,str[i] & 127);
		}
	printf("\n");
	
	printf("Hello World OR 127: \n");
	for(int i=0;str[i]!='\0';i++){
		printf("'%c' (ASCII: %d)->'%c' (ASCII: %d)\n",str[i],str[i],str[i] | 127,str[i] | 127);
		}
		
	printf("\n");	

	printf("Hello World XOR 127: \n");
	for(int i=0;str[i]!='\0';i++){
		printf("'%c' (ASCII: %d)->'%c' (ASCII: %d)\n",str[i],str[i],str[i] ^ 127,str[i] ^ 127);
		}	
}

------------------------------------------------------------------------

CAESAR

//2a.

import java.util.Scanner;

public class ceaser {

    public static String transform(String text, int shift) {
        StringBuilder result = new StringBuilder();
        
        // Ensure the shift is between 0 and 25
        shift = shift % 26;

        for (char character : text.toCharArray()) {
            if (Character.isLetter(character)) {
                char base = (Character.isLowerCase(character)) ? 'a' : 'A';
                result.append((char) ((character - base + shift) % 26 + base));
            } else {
                result.append(character); 
            }
        }
        return result.toString();
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter the text to encrypt: ");
        String text = scanner.nextLine();

        System.out.print("Enter the shift value: ");
        int shift = scanner.nextInt();

        String encryptedText = transform(text, shift);
        
        // Decrypting with the correct shift
        String decryptedText = transform(encryptedText, 26 - (shift % 26));

        System.out.println("Encrypted Text: " + encryptedText);
        System.out.println("Decrypted Text: " + decryptedText);

        scanner.close();
    }
}


------------------------------------------------------------------------------------------------------

PLAYFAIR

//2b
import java.util.*;

public class p2b {
    private char[][] matrix = new char[5][5];

    public p2b(String key) {
        key = formatKey(key);
        buildMatrix(key);
        printMatrix(); 
    }

    private String formatKey(String key) {
        StringBuilder result = new StringBuilder();
        key = key.toUpperCase().replaceAll("[^A-Z]", "").replace("J", "I");
        Set<Character> used = new HashSet<>();
        for (char c : key.toCharArray()) {
            if (!used.contains(c)) {
                used.add(c);
                result.append(c);
            }
        }
        for (char c = 'A'; c <= 'Z'; c++) {
            if (c == 'J') continue;
            if (!used.contains(c)) {
                used.add(c);
                result.append(c);
            }
        }
        return result.toString();
    }

    private void buildMatrix(String key) {
        int index = 0;
        for (int i = 0; i < 5; i++)
            for (int j = 0; j < 5; j++)
                matrix[i][j] = key.charAt(index++);
    }

    private void printMatrix() {
        System.out.println("\nPlayfair Cipher Matrix:");
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                System.out.print(matrix[i][j] + " ");
            }
            System.out.println();
        }
        System.out.println();
    }

    private int[] getPosition(char c) {
        if (c == 'J') c = 'I';
        for (int i = 0; i < 5; i++)
            for (int j = 0; j < 5; j++)
                if (matrix[i][j] == c)
                    return new int[]{i, j};
        return null;
    }

    private List<String> prepareText(String text) {
        text = text.toUpperCase().replaceAll("[^A-Z]", "").replace("J", "I");
        List<String> pairs = new ArrayList<>();
        int i = 0;
        while (i < text.length()) {
            char a = text.charAt(i++);
            char b = (i < text.length()) ? text.charAt(i) : 'X';
            if (a == b) {
                b = 'X';
            } else {
                i++;
            }
            pairs.add("" + a + b);
        }
        return pairs;
    }

    public String encrypt(String plainText) {
        List<String> pairs = prepareText(plainText);
        StringBuilder encrypted = new StringBuilder();
        for (String pair : pairs) {
            int[] pos1 = getPosition(pair.charAt(0));
            int[] pos2 = getPosition(pair.charAt(1));
            if (pos1[0] == pos2[0]) {
                encrypted.append(matrix[pos1[0]][(pos1[1] + 1) % 5]);
                encrypted.append(matrix[pos2[0]][(pos2[1] + 1) % 5]);
            } else if (pos1[1] == pos2[1]) {
                encrypted.append(matrix[(pos1[0] + 1) % 5][pos1[1]]);
                encrypted.append(matrix[(pos2[0] + 1) % 5][pos2[1]]);
            } else {
                encrypted.append(matrix[pos1[0]][pos2[1]]);
                encrypted.append(matrix[pos2[0]][pos1[1]]);
            }
        }
        return encrypted.toString();
    }

    public String decrypt(String cipherText) {
        List<String> pairs = prepareText(cipherText);
        StringBuilder decrypted = new StringBuilder();
        for (String pair : pairs) {
            int[] pos1 = getPosition(pair.charAt(0));
            int[] pos2 = getPosition(pair.charAt(1));
            if (pos1[0] == pos2[0]) {
                decrypted.append(matrix[pos1[0]][(pos1[1] + 4) % 5]);
                decrypted.append(matrix[pos2[0]][(pos2[1] + 4) % 5]);
            } else if (pos1[1] == pos2[1]) {
                decrypted.append(matrix[(pos1[0] + 4) % 5][pos1[1]]);
                decrypted.append(matrix[(pos2[0] + 4) % 5][pos2[1]]);
            } else {
                decrypted.append(matrix[pos1[0]][pos2[1]]);
                decrypted.append(matrix[pos2[0]][pos1[1]]);
            }
        }
        return decrypted.toString();
    }

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter key: ");
        String key = sc.nextLine();
        p2b cipher = new p2b(key);
        System.out.print("Enter message to encrypt: ");
        String message = sc.nextLine();
        String encrypted = cipher.encrypt(message);
        String decrypted = cipher.decrypt(encrypted);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
        sc.close();
    }
}


-----------------------------------------------------------------------------------------------

VIGENERE

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#define ALPHABET_SIZE 26

void encrypt(char plaintext[], char key[], char ciphertext[]) {
    int i, j = 0;
    int len_plaintext = strlen(plaintext);
    int len_key = strlen(key);

    for (i = 0; i < len_plaintext; i++) {
        if (isalpha(plaintext[i])) {
            char key_char = toupper(key[j % len_key]);
            char plain_char = toupper(plaintext[i]);
            ciphertext[i] = ((plain_char - 'A' + (key_char - 'A')) % ALPHABET_SIZE) + 'A';
            j++;
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[i] = '\0';
}

void decrypt(char ciphertext[], char key[], char plaintext[]) {
    int i, j = 0;
    int len_ciphertext = strlen(ciphertext);
    int len_key = strlen(key);

    for (i = 0; i < len_ciphertext; i++) {
        if (isalpha(ciphertext[i])) {
            char key_char = toupper(key[j % len_key]);
            char cipher_char = toupper(ciphertext[i]);
            plaintext[i] = ((cipher_char - key_char + ALPHABET_SIZE) % ALPHABET_SIZE) + 'A';
            j++;
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
    plaintext[i] = '\0';
}

void print_vigenere_table() {
    char alphabet[ALPHABET_SIZE] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    for (int i = 0; i < ALPHABET_SIZE; i++) {
        for (int j = 0; j < ALPHABET_SIZE; j++) {
            printf("%c ", alphabet[(i + j) % ALPHABET_SIZE]);
        }
        printf("\n");
    }
}

int main() {
    char plaintext[100], key[100], encryptedText[100], decryptedText[100];

    printf("Enter the plaintext: ");
    fgets(plaintext, sizeof(plaintext), stdin);
    plaintext[strcspn(plaintext, "\n")] = '\0';

    printf("Enter the key: ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = '\0';

    print_vigenere_table();

    encrypt(plaintext, key, encryptedText);
    printf("Encrypted Text: %s\n", encryptedText);

    decrypt(encryptedText, key, decryptedText);
    printf("Decrypted Text: %s\n", decryptedText);

    return 0;
}


--------------------------------------------------------------------------------------------

RAIL-FENCE

//3b
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LEN 100

void remove_spaces(char *text, char *no_spaces) {
    int j = 0;
    for (int i = 0; text[i] != '\0'; i++) {
        if (text[i] != ' ') {
            no_spaces[j++] = text[i];
        }
    }
    no_spaces[j] = '\0';
}

void display_rail_matrix(char matrix[][MAX_LEN], int rails, int len) {
    printf("\nRail Fence Zigzag Matrix:\n");
    for (int i = 0; i < rails; i++) {
        for (int j = 0; j < len; j++) {
            if (matrix[i][j] == 0)
                printf("  ");
            else
                printf("%c ", matrix[i][j]);
        }
        printf("\n");
    }
}

void rail_fence_encrypt(char text[], int rails, char encrypted[]) {
    int len = strlen(text);
    if (rails == 1) {
        strcpy(encrypted, text);
        return;
    }

    char rail_matrix[rails][MAX_LEN];
memset(rail_matrix, 0, sizeof(rail_matrix));


    int row = 0, col = 0, direction = 1;

    for (int i = 0; i < len; i++) {
        rail_matrix[row][col++] = text[i];

        if (row == 0) direction = 1;
        else if (row == rails - 1) direction = -1;

        row += direction;
    }

    display_rail_matrix(rail_matrix, rails, len);

    int index = 0;
    for (int i = 0; i < rails; i++) {
        for (int j = 0; j < len; j++) {
            if (rail_matrix[i][j] != 0) {
                encrypted[index++] = rail_matrix[i][j];
            }
        }
    }
    encrypted[index] = '\0';
}

void rail_fence_decrypt(char text[], int rails, char decrypted[], const char *original_text) {
    int len = strlen(text);
    if (rails == 1) {
        strcpy(decrypted, text);
        return;
    }

    char rail_matrix[rails][MAX_LEN];
memset(rail_matrix, 0, sizeof(rail_matrix));

    int row = 0, col = 0, direction = 1;

    for (int i = 0; i < len; i++) {
        rail_matrix[row][col++] = '*';

        if (row == 0) direction = 1;
        else if (row == rails - 1) direction = -1;

        row += direction;
    }

    int index = 0;
    for (int i = 0; i < rails; i++) {
        for (int j = 0; j < len; j++) {
            if (rail_matrix[i][j] == '*' && index < len) {
                rail_matrix[i][j] = text[index++];
            }
        }
    }

    row = 0, col = 0, direction = 1;
    index = 0;
    for (int i = 0; i < len; i++) {
        decrypted[index++] = rail_matrix[row][col++];

        if (row == 0) direction = 1;
        else if (row == rails - 1) direction = -1;

        row += direction;
    }
    decrypted[index] = '\0';

    int j = 0;
    for (int i = 0; original_text[i] != '\0'; i++) {
        if (original_text[i] == ' ') {
            memmove(decrypted + j + 1, decrypted + j, strlen(decrypted) - j + 1);
            decrypted[j] = ' ';
            j++;
        }
        j++;
    }
}

int main() {
    char text[MAX_LEN], encrypted[MAX_LEN], decrypted[MAX_LEN], no_spaces[MAX_LEN];
    int rails;

    printf("Enter the message to encrypt: ");
    fgets(text, sizeof(text), stdin);
    text[strcspn(text, "\n")] = '\0';

    printf("Enter the number of rails: ");
    scanf("%d", &rails);
    getchar();

    remove_spaces(text, no_spaces);

    rail_fence_encrypt(no_spaces, rails, encrypted);
    printf("\nEncrypted Message: %s\n", encrypted);

    rail_fence_decrypt(encrypted, rails, decrypted, text);
    printf("Decrypted Message: %s\n", decrypted);

    return 0;
}


---------------------------------------------------------------------------------------------

HILL CIPHER

//4
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MOD 26

int SIZE;

int mod26(int x) {
    return (x % MOD + MOD) % MOD;
}

int determinant(int m[10][10], int n) {
    if (n == 1) {
        return mod26(m[0][0]);
    }
    int det = 0, temp[10][10];
    int sign = 1;
    for (int f = 0; f < n; f++) {
        int subi = 0;
        for (int i = 1; i < n; i++) {
            int subj = 0;
            for (int j = 0; j < n; j++) {
                if (j == f) {
                    continue;
                }
                temp[subi][subj] = m[i][j];
                subj++;
            }
            subi++;
        }
        det += sign * m[0][f] * determinant(temp, n - 1);
        sign = -sign;
    }
    return mod26(det);
}

int modInverse(int a) {
    for (int x = 1; x < MOD; x++) {
        if (mod26(a * x) == 1) {
            return x;
        }
    }
    return -1;
}

void cofactorTranspose(int m[10][10], int adj[10][10], int n) {
    if (n == 1) {
        adj[0][0] = 1;
        return;
    }
    int temp[10][10];
    int sign;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            int subi = 0, subj = 0;
            for (int row = 0; row < n; row++) {
                for (int col = 0; col < n; col++) {
                    if (row != i && col != j) {
                        temp[subi][subj++] = m[row][col];
                        if (subj == n - 1) {
                            subj = 0;
                            subi++;
                        }
                    }
                }
            }
            sign = ((i + j) % 2 == 0) ? 1 : -1;
            adj[j][i] = mod26(sign * determinant(temp, n - 1));
        }
    }
}

int matrixInverse(int key[10][10], int inv[10][10]) {
    int det = determinant(key, SIZE);
    int detInv = modInverse(det);
    if (detInv == -1) {
        printf("Error: Key matrix is not invertible. Cannot decrypt.\n");
        return 0;
    }
    int adj[10][10];
    cofactorTranspose(key, adj, SIZE);
    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            inv[i][j] = mod26(adj[i][j] * detInv);
        }
    }
    return 1;
}

void matrixMultiply(int result[10][1], int matrix[10][10], int vector[10][1]) {
    for (int i = 0; i < SIZE; i++) {
        result[i][0] = 0;
        for (int j = 0; j < SIZE; j++) {
            result[i][0] += matrix[i][j] * vector[j][0];
        }
        result[i][0] = mod26(result[i][0]);
    }
}

void processPlaintext(char* raw, char* clean) {
    int j = 0;
    for (int i = 0; raw[i]; i++) {
        if (isalpha(raw[i])) {
            clean[j++] = toupper(raw[i]);
        }
    }
    while (j % SIZE != 0) {
        clean[j++] = 'X';
    }
    clean[j] = '\0';
}

void HillCipherEncrypt(char message[], int keyMatrix[10][10]) {
    char clean[100], CipherText[100];
    processPlaintext(message, clean);
    int len = strlen(clean);
    int messageVector[10][1], cipherMatrix[10][1];
    for (int i = 0; i < len; i += SIZE) {
        for (int j = 0; j < SIZE; j++) {
            messageVector[j][0] = (clean[i + j] - 'A') % 26;
        }
        matrixMultiply(cipherMatrix, keyMatrix, messageVector);
        for (int j = 0; j < SIZE; j++) {
            CipherText[i + j] = (cipherMatrix[j][0] + 'A');
        }
    }
    CipherText[len] = '\0';
    printf("Ciphertext: %s\n", CipherText);
}

void HillCipherDecrypt(char cipher[], int keyMatrix[10][10]) {
    int invKey[10][10];
    if (!matrixInverse(keyMatrix, invKey)) {
        return;
    }
    int len = strlen(cipher);
    int messageVector[10][1], plainMatrix[10][1];
    char PlainText[100];
    for (int i = 0; i < len; i += SIZE) {
        for (int j = 0; j < SIZE; j++) {
            messageVector[j][0] = (cipher[i + j] - 'A') % 26;
        }
        matrixMultiply(plainMatrix, invKey, messageVector);
        for (int j = 0; j < SIZE; j++) {
            PlainText[i + j] = (plainMatrix[j][0] + 'A');
        }
    }
    PlainText[len] = '\0';
    printf("Decrypted text: %s\n", PlainText);
}

int main() {
    char message[100], cipher[100];
    int keyMatrix[10][10];
    printf("Enter the order of the matrix (e.g., 2 or 3): ");
    scanf("%d", &SIZE);
    if (SIZE < 2 || SIZE > 10) {
        printf("Error: Invalid matrix size. Please enter a value between 2 and 10.\n");
        return 0;
    }
    getchar();
    printf("Enter plaintext: ");
    fgets(message, sizeof(message), stdin);
    size_t len = strlen(message);
    if (len > 0 && message[len - 1] == '\n') {
        message[len - 1] = '\0';
    }
    printf("Enter the %dx%d key matrix (0-25 values):\n", SIZE, SIZE);
    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            printf("Enter key[%d][%d]: ", i, j);
            scanf("%d", &keyMatrix[i][j]);
            keyMatrix[i][j] = mod26(keyMatrix[i][j]);
        }
    }
    HillCipherEncrypt(message, keyMatrix);
    printf("\nEnter ciphertext to decrypt: ");
    scanf("%s", cipher);
    HillCipherDecrypt(cipher, keyMatrix);
    return 0;
}

3 3
2 5

7 9
2 3

6 24 1
13 16 10
20 17 15

2 4 5
9 2 1
3 17 7


--------------------------------------------------------------------------------------------------

SDES

import java.util.*;

public class SDES {
    static int[] P10, P8, P4, IP, IP_INV, EP;
    static int[][] S0, S1;
    static String k1, k2;

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        P10 = readPermutation(sc, "Enter P10 (10 space-separated indices): ", 10);
        P8 = readPermutation(sc, "Enter P8 (8 space-separated indices): ", 8);
        P4 = readPermutation(sc, "Enter P4 (4 space-separated indices): ", 4);
        IP = readPermutation(sc, "Enter IP (8 space-separated indices): ", 8);
        IP_INV = readPermutation(sc, "Enter IP Inverse (8 space-separated indices): ", 8);
        EP = readPermutation(sc, "Enter EP (8 space-separated indices): ", 8);
        S0 = readSBox(sc, "Enter S0 (4 rows, 4 values each): ");
        S1 = readSBox(sc, "Enter S1 (4 rows, 4 values each): ");

        System.out.print("Enter 10-bit key: ");
        String key = sc.next();

        System.out.print("Enter 8-bit plaintext: ");
        String pt = sc.next();

        generateKeys(key);

        String ct = fk(pt, k1, k2);
        System.out.println("Ciphertext: " + ct);
    }

    static int[] readPermutation(Scanner sc, String prompt, int size) {
        System.out.print(prompt);
        int[] perm = new int[size];
        for (int i = 0; i < size; i++)
            perm[i] = sc.nextInt();
        return perm;
    }

    static int[][] readSBox(Scanner sc, String prompt) {
        System.out.println(prompt);
        int[][] box = new int[4][4];
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                box[i][j] = sc.nextInt();
        return box;
    }

    static void generateKeys(String key) {
        key = permute(key, P10);
        String ls1 = leftShift(key.substring(0, 5), 1) + leftShift(key.substring(5), 1);
        k1 = permute(ls1, P8);
        String ls2 = leftShift(leftShift(ls1.substring(0, 5), 1), 1) + leftShift(leftShift(ls1.substring(5), 1), 1);
        k2 = permute(ls2, P8);
    }

    static String fk(String text, String k1, String k2) {
        text = permute(text, IP);
        String[] halves = { text.substring(0, 4), text.substring(4) };
        String temp = xor(halves[0], f(halves[1], k1));
        text = halves[1] + temp;
        halves[0] = text.substring(0, 4);
        halves[1] = text.substring(4);
        temp = xor(halves[0], f(halves[1], k2));
        return permute(temp + halves[1], IP_INV);
    }

    static String f(String r, String k) {
        String ep = permute(r, EP);
        String x = xor(ep, k);
        String s0 = sBox(x.substring(0, 4), S0);
        String s1 = sBox(x.substring(4), S1);
        return permute(s0 + s1, P4);
    }

    static String sBox(String bits, int[][] s) {
        int row = Integer.parseInt("" + bits.charAt(0) + bits.charAt(3), 2);
        int col = Integer.parseInt("" + bits.charAt(1) + bits.charAt(2), 2);
        return String.format("%2s", Integer.toBinaryString(s[row][col])).replace(' ', '0');
    }

    static String permute(String input, int[] p) {
        StringBuilder sb = new StringBuilder();
        for (int i : p)
            sb.append(input.charAt(i - 1));
        return sb.toString();
    }

    static String leftShift(String s, int n) {
        return s.substring(n) + s.substring(0, n);
    }

    static String xor(String a, String b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < a.length(); i++)
            sb.append(a.charAt(i) == b.charAt(i) ? '0' : '1');
        return sb.toString();
    }
}




P10      = 3 5 2 7 4 10 1 9 8 6  
P8       = 6 3 7 4 8 5 10 9  
P4       = 2 4 3 1  
IP       = 2 6 3 1 4 8 5 7  
IP_INV   = 4 1 3 5 7 2 8 6  
EP       = 4 1 2 3 2 3 4 1  

S0 =
    1 0 3 2
    3 2 1 0
    0 2 1 3
    3 1 3 2

S1 =
    0 1 2 3
    2 0 1 3
    3 0 1 0
    2 1 0 3
