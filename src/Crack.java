import java.math.BigInteger;  
import java.nio.charset.StandardCharsets; 
import java.security.MessageDigest;  
import java.security.NoSuchAlgorithmException;  
import java.lang.IllegalArgumentException;
import java.lang.RuntimeException;
import java.util.NoSuchElementException;
import java.io.File;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Scanner;
import java.util.List;
import java.util.LinkedList;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.HashMap;
import java.util.Collections;
import java.util.Comparator;
import java.util.stream.Collectors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This program is for the purpose of using lists of leaked passwords to try and guess the passwords of user given as input.
 * You can modify the constants listed at the beginning of the program if you wish to have more information provided by the
 * program as it completes its execution.
 * 
 * Running this program, you should be aware that it requires at least two files, where the first file contains lines in the 
 * format of 'user01:hashedPassword' and the second file contains possible passwords (such as password123). Note that you can
 * provide multiple files consisting of possible passwords.
 * 
 * Example: java Crack "userPwHashes.txt" "possiblePws1.txt" "possiblePws2.txt"
 * 
 * The methods getHash and toHexString is adapted from a piece of code found on GeeksForGeeks.
 * @see https://www.geeksforgeeks.org/sha-256-hash-in-java/
 */
class Crack {

    // Constants used for debugging
    private final static boolean DEBUG_ALT_INPUT = false;    // set to true when checking possible passwords from https://haveibeenpwned.com/Passwords
    private final static boolean DEBUG_PRINT_MORE = true;   // set to true if you want to be given more information about each possible password file
    private final static boolean DEBUG_USE_TIMING = true;   // set to true if you wish to time each file containing possible passwords

    // Other constants
    private static final ExecutorService executor =         // used for multi-threading
        Executors.newCachedThreadPool();    
    private static final String HASH_METHOD = 
        // "MD5";
        "SHA-256";
        // "SHA-1";

    // keys are password hashes, values are either usernames or passwords
    private static Map<String,String> userPwMapping;
    private static Map<String,String> resultMapping;
    private static long START_TIME; // Used for timing

    public static void main(String[] args) {
        if(args.length < 2) {
            throw new IllegalArgumentException("Program requires at least two files to function (one containing user-pwHashes and another containing leaked passwords!");
        } else {
            // Pre-defining variables
            userPwMapping = new HashMap<>();            // Map of <PwHash, List of <Users>>
            resultMapping = new ConcurrentHashMap<>();  // Map of <PwHash, List of <Users>>
            final int[] findsPerFile = new int[args.length-1];
            final int[] linesPerFile = new int[args.length-1];
            final float[] timePerFile = new float[args.length-1];
            if(DEBUG_USE_TIMING) { START_TIME = System.nanoTime(); }

            // Read user-passwordHashes and store in mapping
            readUserPwHashes(args);

            // Read lines of possible passwords from files given in argument list
            List<Callable<Void>> tasks = new ArrayList<>();
            for(int i = 1; i < args.length; i++) {
                final int id = i;
                tasks.add(() -> {
                        taskExecution(id, args, findsPerFile, linesPerFile, timePerFile);
                        return null;
                    }
                );
            }

            // Wait for tasks to finish
            try {
                executor.invokeAll(tasks);
            } catch (InterruptedException exn) { 
                System.out.println("Interrupted: " + exn);
            }

            // Sort results according to number in username
            List<Result> results = new LinkedList<>();
            for (String pwHash : resultMapping.keySet()) {
                results.add(new Result(userPwMapping.get(pwHash), resultMapping.get(pwHash), pwHash));
            }
            Collections.sort(results);
            printOutResults(results, args, findsPerFile, linesPerFile, timePerFile);
        }
    }

    private static void readUserPwHashes(String[] args) {
        try (Scanner file1 = new Scanner(new File(args[0]))) {
            String line, hash, username; int start;
            while(file1.hasNext()) {
                line = file1.nextLine();
                start = line.indexOf(":", 0);
                if (start == -1) {throw new IllegalArgumentException("First file should contain user:hash mappings!");}
                username = line.substring(0, start);
                hash = line.substring(start+1, line.length());
                userPwMapping.put(hash,username);
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            throw new RuntimeException("Execution halted due to missing input file of usernames and their password hashes!");
        }
    }

    private static void taskExecution(int id, String[] args, int[] findsPerFile, int[] linesPerFile, float[] timePerFile) {
        try (BufferedReader scanner = new BufferedReader(new FileReader(args[id]))) {
            long start;
            if (DEBUG_USE_TIMING) { start = System.nanoTime(); }
            String line, hash;
            int count = 0, lines = 0;
            while((line = scanner.readLine()) != null) {
                if(DEBUG_ALT_INPUT) {
                    line = line.substring(line.indexOf(":")+1,line.length());
                }
                hash = toHexString(getHash(line));
                
                if(userPwMapping.containsKey(hash)) {
                    resultMapping.putIfAbsent(hash,line);
                    count++;
                }
                lines++;
            }
            findsPerFile[id-1] = count;
            if (DEBUG_PRINT_MORE) {
                linesPerFile[id-1] = lines;
            }
            if (DEBUG_USE_TIMING) {
                timePerFile[id-1] = (0.0f+System.nanoTime()-start)/1_000_000_000f;
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Exception thrown for incorrect algorithm: " + e);  
        } 
    }

    private static void printOutResults(List<Result> results, String[] args, int[] findsPerFile, int[] linesPerFile, float[] timePerFile) {
        // Print out results (along with additional details if needed)
        for (Result out : results) { System.out.println(out.toString()); }
        if (DEBUG_PRINT_MORE) {
            float time = ((DEBUG_USE_TIMING) ? ((0.0f+System.nanoTime()-START_TIME)/1_000_000_000f): 0.0f);
            System.out.printf("Found %d unique passwords in %d files (out of %d given passwords).\n",resultMapping.size(),args.length-1,userPwMapping.size());
            int totalFinds = 0;
            for (int i = 0; i < findsPerFile.length; i++) {
                totalFinds += findsPerFile[i];
                System.out.printf("'%s' contained %d matches (checked %d lines", args[i+1], findsPerFile[i], linesPerFile[i]);
                if(DEBUG_USE_TIMING) {
                    System.out.printf(" in %f seconds", timePerFile[i]);
                }
                System.out.printf(").\n");
            }
            System.out.printf("In total, there was %d matches that was found in multiple files.\n",totalFinds-resultMapping.size());
            if (DEBUG_USE_TIMING) { System.out.printf("Total run time: %f seconds\n", time); }
            List<String> missings = findUsersWithPwsNotFound(userPwMapping, resultMapping);
            int counter = 0;
            if(missings.size() != 0) {
                System.out.printf("\nThe following users did not have their passwords cracked:\n");
            }
            for (String missing : missings) {
                System.out.printf("[%s]", missing);
                if(counter % 10 == 9) { System.out.println(); }
                counter++;
            }
            System.out.println();
        }
    }

    private static List<String> findUsersWithPwsNotFound(Map<String,String> userPwMap, Map<String,String> guessedPwMap) {
        List<String> results = new LinkedList<>();
        for (String userHashPw : userPwMap.keySet()) {
            if(!guessedPwMap.containsKey(userHashPw)) {
                results.add(userPwMap.get(userHashPw));
            }
        }
        String regex = "([a-zA-Z]*)(\\d*)";
        Pattern r = Pattern.compile(regex);
        Comparator<String> cmp = new Comparator<String>() {
            public int compare(String o1, String o2) {
                Matcher m1 = r.matcher(o1);
                Matcher m2 = r.matcher(o2);
                int id1, id2;
                if(m1.find() && m2.find()) {
                    id1 = Integer.parseInt(m1.group(2));
                    id2 = Integer.parseInt(m2.group(2));
                    return ((id1 < id2) ? -1 : (id1 > id2) ? 1 : 0);
                } else {
                    return o1.compareTo(o2);
                }
            }
        };
        Collections.sort(results, cmp);
        return results;
    }

    public static byte[] getHash(String input) throws NoSuchAlgorithmException 
    {  
        // Static getInstance method is called with hashing SHA  
        MessageDigest md = MessageDigest.getInstance(HASH_METHOD);  
  
        // digest() method called  
        // to calculate message digest of an input  
        // and return array of byte 
        return md.digest(input.getBytes(StandardCharsets.UTF_8));  
    } 
    
    public static String toHexString(byte[] hash) 
    { 
        // Convert byte array into signum representation  
        BigInteger number = new BigInteger(1, hash);  
  
        // Convert message digest into hex value  
        StringBuilder hexString = new StringBuilder(number.toString(16));  
  
        // Pad with leading zeros 
        while (hexString.length() < 32)  
        {  
            hexString.insert(0, '0');  
        }  
  
        return hexString.toString();  
    } 

    // This class is used as a placeholder for formating the output (using a regex to order them according to number)
    static class Result implements Comparable<Result> {
        static final String regex = "([a-zA-Z]*)(\\d*)";
        static final Pattern r = Pattern.compile(regex);
        String user, pw, hash;
        int id = -1;

        Result(String user, String pw, String hash) {
            this.user = user;
            this.pw = pw; this.hash = hash;
            Matcher m = r.matcher(user);
            if(m.find()) {
                id = Integer.parseInt(m.group(2));
            }
        }

        public int compareTo(Result other){
            return ((this.id < other.id) ? -1 : (this.id > other.id) ? 1 : 0);
        }

        public String toString() {
            return String.format("%s:%s (hash:%s)",user,pw,hash);
        }
    }
}