package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

import java.util.LinkedList;
import java.util.concurrent.atomic.AtomicInteger;

public class BlackListThread extends Thread{
    private String ipaddress;
    private int BLACK_LIST_ALARM_COUNT;
    private LinkedList<Integer> blackListOcurrences;
    private int lowerRange;
    private int topRange;
    public static AtomicInteger ocurrencesCount = new AtomicInteger(0);
    public static AtomicInteger checkedListsCount = new AtomicInteger(0);

    public BlackListThread(String ipaddress, int lowerRange, int topRange, int BLACK_LIST_ALARM_COUNT){
        this.ipaddress = ipaddress;
        this.lowerRange = lowerRange;
        this.topRange = topRange;
        this.BLACK_LIST_ALARM_COUNT = BLACK_LIST_ALARM_COUNT;
        this.blackListOcurrences = new LinkedList<>();
    }

    @Override
    public void run() {
        check();
    }

    public void check(){
        HostBlacklistsDataSourceFacade skds = HostBlacklistsDataSourceFacade.getInstance();
        for (int i=lowerRange; i < topRange && ocurrencesCount.get() < BLACK_LIST_ALARM_COUNT; i++){
            checkedListsCount.addAndGet(1);
            if (skds.isInBlackListServer(i, ipaddress)){
                blackListOcurrences.add(i);
                ocurrencesCount.addAndGet(1);
            }
        }
    }

    public LinkedList<Integer> getBlackListOcurrences() {
        return blackListOcurrences;
    }
}
