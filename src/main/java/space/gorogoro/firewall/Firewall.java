package space.gorogoro.firewall;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

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
  List<String> blockNetsetIpv6List = new ArrayList<String>();
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
      setBlockNetsetList(config.getStringList("block-netset-file-list"));
      unblockIpAddrList = config.getStringList("unblock-ip-addr-list");
      unblockUuidList = config.getStringList("unblock-uuid-list");

    } catch (Exception e) {
      logStackTrace(e);
    }
  }

  @EventHandler
  public void onAsyncPlayerPreLoginEvent(AsyncPlayerPreLoginEvent event){
    try {
      String ipAddress = event.getAddress().getHostAddress().toString();

      if(unblockIpAddrList.contains(ipAddress) == false
        && unblockUuidList.contains(event.getUniqueId().toString()) == false) {
        // TODO: write block logic
        event.disallow(Result.KICK_OTHER, config.getString("message-kick"));
      }

    } catch (Exception e) {
      logStackTrace(e);
    }
  }

  private boolean isIpv4(String str) {
    try {
      if (InetAddress.getByName(str) instanceof Inet4Address) {
        return true;
      }
    } catch (UnknownHostException e) {
      return false;
    }
    return false;
  }

  private boolean isIpv6(String str) {
    try {
      if (InetAddress.getByName(str) instanceof Inet6Address) {
        return true;
      }
    } catch (UnknownHostException e) {
      return false;
    }
    return false;
  }

  private void logStackTrace(Exception e){
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    e.printStackTrace(pw);
    pw.flush();
    getLogger().log(Level.WARNING, sw.toString());
  }

  private void setBlockNetsetList(List<String> fileList) {
    try {
      blockNetsetIpv4List = null;
      blockNetsetIpv6List = null;
      for(String fileName : fileList){
        File f = new File(getDataFolder() + File.separator + fileName);
        if(!f.exists()) {
          continue;
        }

        List<String> lines = Files.readAllLines(f.toPath());
        for(String line: lines) {
          if(isIpv4(line) && !blockNetsetIpv4List.contains(line)) {
            blockNetsetIpv4List.add(line);
          } else if(isIpv6(line) && !blockNetsetIpv6List.contains(line)) {
            blockNetsetIpv6List.add(line);
          }
        }
      }
    } catch (Exception e) {
      logStackTrace(e);
    }
  }
}
