package com.scalesec.vulnado;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Cowsay {
  public static String run(String input) {
    // Use argv list form of ProcessBuilder (no shell interpreter) to prevent
    // command injection. The cowsay binary receives 'input' as a discrete
    // argument rather than part of a shell-interpolated string, so shell
    // metacharacters in user input are never interpreted by a shell.
    ProcessBuilder processBuilder = new ProcessBuilder("/usr/games/cowsay", input);

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
