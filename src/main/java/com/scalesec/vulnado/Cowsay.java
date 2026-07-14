package com.scalesec.vulnado;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Cowsay {
  public static String run(String input) {
    // Fix: Pass arguments as a list to ProcessBuilder instead of using bash -c with
    // string concatenation. This prevents command injection because the OS treats
    // input as a literal argument to cowsay, never as a shell command.
    ProcessBuilder processBuilder = new ProcessBuilder("/usr/games/cowsay", input);
    System.out.println("/usr/games/cowsay " + input);

    StringBuilder output = new StringBuilder();

    try {
      Process process = processBuilder.start();
      BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

      String line;
      while ((line = reader.readLine()) != null) {
        output.append(line + "\n");
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return output.toString();
  }
}
