package com.scalesec.vulnado;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Cowsay {
  public static String run(String input) {
    // Pass input as a discrete argument in the argv list — no shell interpreter,
    // no string concatenation into a shell command string.
    // This is the SAST-recognized safe form: ProcessBuilder with a List<String>
    // where the executable is hardcoded and user data is a separate element,
    // so the OS never interprets shell metacharacters in the input.
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
