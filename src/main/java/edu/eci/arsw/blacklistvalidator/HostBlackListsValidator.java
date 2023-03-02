/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author hcadavid
 */
public class HostBlackListsValidator{
    private static final int BLACK_LIST_ALARM_COUNT=5;
    private HostBlacklistsDataSourceFacade skds=HostBlacklistsDataSourceFacade.getInstance();

    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());

    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     * @param ipaddress suspicious host's IP address.
     * @return  Blacklists numbers where the given host's IP address was found.
     */


    public List<Integer> checkHost(String ipaddress, int N) throws InterruptedException {
        BlackListThread[] blackThreads = new BlackListThread[N];
        List<Integer> blackListOcurrences = new LinkedList<>();
        createAndStartThreads(N, ipaddress, blackThreads);
        waitForOthers(blackThreads, N);
        report(ipaddress);
        joinOccurrences(blackListOcurrences, blackThreads, N);
        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}", new Object[]{BlackListThread.checkedListsCount.get(), skds.getRegisteredServersCount()});
        return blackListOcurrences;
    }

    private void createAndStartThreads(int N, String ipaddress, BlackListThread[] blackThreads){
        for(int i = 0; i < N; i++){
            int lowerRange = skds.getRegisteredServersCount() / N * i;
            int topRange = skds.getRegisteredServersCount() / N * (i + 1);
            if(i == N -1 && skds.getRegisteredServersCount() % N != 0){
                topRange = skds.getRegisteredServersCount();
            }
            BlackListThread blackThread = new BlackListThread(ipaddress, lowerRange, topRange, BLACK_LIST_ALARM_COUNT);
            blackThread.start();
            blackThreads[i] = blackThread;
        }
    }

    private void report(String ipaddress){
        if (BlackListThread.ocurrencesCount.get() >= BLACK_LIST_ALARM_COUNT){
            skds.reportAsNotTrustworthy(ipaddress);
        }
        else{
            skds.reportAsTrustworthy(ipaddress);
        }
    }

    private void waitForOthers(BlackListThread[] blackThreads, int N) throws InterruptedException {
        for(int i = 0; i < N; i++){
            blackThreads[i].join();
        }
    }

    private void joinOccurrences(List<Integer> blackListOcurrences, BlackListThread[] blackThreads, int N){
        for(int i = 0; i < N; i++){
            blackListOcurrences.addAll(blackThreads[i].getBlackListOcurrences());
        }
    }

}
