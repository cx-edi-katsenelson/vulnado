package com.scalesec.vulnado;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;

public class Cowsay {
  public static String run(String input) {
    // Use argument list form (no shell) to prevent command injection (CWE-78).
    // The user-supplied input is passed as a discrete argument to cowsay,
    // so the shell never interprets it.
    List<String> cmd = Arrays.asList("/usr/games/cowsay", input);
    ProcessBuilder processBuilder = new ProcessBuilder(cmd);

    StringBuilder output = new StringBuilder();

    try {
      Process process = processBuilder.start();
      BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

      String line;
      while ((line = reader.readLine()) != null) {
        output.append(line).append("\n");
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return output.toString();
  }
}
