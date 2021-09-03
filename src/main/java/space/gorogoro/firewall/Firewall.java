package space.gorogoro.firewall;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent.Result;
import org.bukkit.plugin.java.JavaPlugin;

public class Firewall extends JavaPlugin implements Listener{
  FileConfiguration config;
  List<String> blockNetsetIpv4List = new ArrayList<String>();
  List<String> unblockIpAddrList = new ArrayList<String>();
  List<String> unblockUuidList = new ArrayList<String>();

  @Override
  public boolean onCommand( CommandSender sender, Command commandInfo, String label, String[] args) {
    // Return true:Success false:Show the usage set in plugin.yml
    try{
      if(!commandInfo.getName().equals("firewall")) {
        return true;
      }

      if(!sender.isOp()) {
        return true;
      }

      if(args.length != 1) {
        return false;
      }

      if(args[0] == "reload") {
        onDisable();
        onEnable();
        sender.sendMessage("Reload complete.");
      }

    } catch (Exception e) {
      logStackTrace(e);
    }
    return true;
  }

  @Override
  public void onDisable(){
    getLogger().info("The Plugin Has Been Disabled!");
  }

  @Override
  public void onEnable(){
    try{
      getLogger().info("The Plugin Has Been Enabled!");
      getServer().getPluginManager().registerEvents(this, this);

      // If there is no setting file, it is created
      if(!getDataFolder().exists()){
        getDataFolder().mkdir();
      }
      File configFile = new File(getDataFolder() + File.separator + "config.yml");
      if(!configFile.exists()){
        saveDefaultConfig();
      }

      config = getConfig();
      loadBlockNetsetList();
      unblockIpAddrList = config.getStringList("unblock-ip-addr-list");
      unblockUuidList = config.getStringList("unblock-uuid-list");

    } catch (Exception e) {
      logStackTrace(e);
    }
  }

  @EventHandler
  public void onAsyncPlayerPreLoginEvent(AsyncPlayerPreLoginEvent event){
    try {
      String addr = event.getAddress().getHostAddress().toString();

      if(unblockIpAddrList.contains(addr) == false
        && unblockUuidList.contains(event.getUniqueId().toString()) == false) {
        for(String cidr:blockNetsetIpv4List) {
          if(cidrInIpv4(addr, cidr)) {
            event.disallow(Result.KICK_OTHER, config.getString("message-kick"));
            return;
          }
        }
      }
    } catch (Exception e) {
      logStackTrace(e);
    }
  }

  private void loadBlockNetsetList() {
    try {
      blockNetsetIpv4List = null;
      for(String fileName : config.getStringList("block-netset-file-list")){
        File f = new File(getDataFolder() + File.separator + fileName);
        if(!f.exists()) {
          continue;
        }

        List<String> lines = Files.readAllLines(f.toPath());
        for(String line: lines) {
          if(isIpv4(line) && !blockNetsetIpv4List.contains(line)) {
            blockNetsetIpv4List.add(line);
          }
        }
      }
    } catch (Exception e) {
      logStackTrace(e);
    }
  }

  private static boolean isIpv4(String str) {
    try {
      if (InetAddress.getByName(str) instanceof Inet4Address) {
        return true;
      }
    } catch (UnknownHostException e) {
      return false;
    }
    return false;
  }

  private static boolean cidrInIpv4(String addr, String cidr) {
    String[] range = cidrToIpv4(cidr);
    if(ipv4ToLong(range[0]) <= ipv4ToLong(addr) && ipv4ToLong(addr) <= ipv4ToLong(range[1])) {
      return true;
    }
    return false;
  }

  private static String[] cidrToIpv4(String str) {
    String[] arrIp = str.split("/");
    Long start = ipv4ToLong(arrIp[0]);
    int subNetMask = 32;
    if (arrIp.length == 2) {
      subNetMask = Integer.parseInt(arrIp[1]);
    }
    Long num = pow(2, 32 - subNetMask);
    Long end = start + num - 1;
    String[] ret = {arrIp[0], longToIpv4(end)};
    return ret;
  }

  private static long ipv4ToLong(String str) {
    String[] arrAddr = str.split("\\.");
    Long num = 0L;
    for (int i=0;i<arrAddr.length;i++) {
      int power = 3-i;
      num += ((Integer.parseInt(arrAddr[i]) % 256) * pow(256,power));
    }
    return num;
  }

  private static String longToIpv4(Long longIp){
    return String.format(
      "%d.%d.%d.%d",
      ((longIp >> 24) & 0xFF),
      ((longIp >> 16) & 0xFF),
      ((longIp >> 8) & 0xFF),
      (longIp & 0xFF)
    );
  }

  private static long pow(int number, int power) {
    if(power == 0) {
      return 1;
    }
    int result = number;
    while(power > 1) {
      result*=number;
      power--;
    }
    return (long)result;
  }

  private static void logStackTrace(Exception e){
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    e.printStackTrace(pw);
    pw.flush();
    Bukkit.getLogger().log(Level.WARNING, sw.toString());
  }
}
