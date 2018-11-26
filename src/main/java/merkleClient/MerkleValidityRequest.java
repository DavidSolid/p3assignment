package merkleClient;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
//import java.util.stream.*;

public class MerkleValidityRequest {

	/**
	 * IP address of the authority
	 * */
	private final String authIPAddr;
	/**
	 * Port number of the authority
	 * */
	private final int  authPort;
	/**
	 * Hash value of the merkle tree root. 
	 * Known before-hand.
	 * */
	private final String mRoot;
	/**
	 * List of transactions this client wants to verify 
	 * the existence of.
	 * */
	private List<String> mRequests;
	
	/**
	 * Sole constructor of this class - marked private.
	 * */
	private MerkleValidityRequest(Builder b){
		this.authIPAddr = b.authIPAddr;
		this.authPort = b.authPort;
		this.mRoot = b.mRoot;
		this.mRequests = b.mRequest;
	}
	
	/**
	 * <p>Method implementing the communication protocol between the client and the authority.</p>
	 * <p>The steps involved are as follows:</p>
	 * 		<p>0. Opens a connection with the authority</p>
	 * 	<p>For each transaction the client does the following:</p>
	 * 		<p>1.: asks for a validityProof for the current transaction</p>
	 * 		<p>2.: listens for a list of hashes which constitute the merkle nodes contents</p>
	 * 	<p>Uses the utility method {@link #isTransactionValid(String, String, List<String>) isTransactionValid} </p>
	 * 	<p>method to check whether the current transaction is valid or not.</p>
	 * */
	public Map<Boolean, List<String>> checkWhichTransactionValid() throws IOException {
		Map<Boolean,List<String>> out= new HashMap<Boolean,List<String>>();
		out.put(true,new ArrayList<String>());
		out.put(false,new ArrayList<String>());
		InetSocketAddress address = new InetSocketAddress(authIPAddr,authPort);
		for(String toverify : mRequests){
			List<String> hashlist=new ArrayList<String>();
			SocketChannel auth = SocketChannel.open(address);
			ByteBuffer output=ByteBuffer.wrap(toverify.getBytes());
			auth.write(output);
			ByteBuffer input=ByteBuffer.allocate(256);
			while(auth.read(input)!=-1){
				String hash=new String(input.array()).trim();
				hashlist.add(hash);
				System.out.println("Ricevuto hash: "+hash);
				input.clear();
			}
			auth.close();
			System.out.println("Tutti gli hash ricevuti");
			if(isTransactionValid(toverify,hashlist)){
				out.get(true).add(toverify);
			}
			else{
				out.get(false).add(toverify);
			}
		}
		return out;
		//functional approach
		/*return mRequests.stream().collect(Collectors.partitioningBy((t)->{
			ByteBuffer output=ByteBuffer.wrap(t.getBytes());
			auth.write(output);
			List<String> hashlist=new ArrayList<String>();
			ByteBuffer input=ByteBuffer.allocate(256);
			while(auth.read(input)!=-1){
				if(input.remaining()==0){
					String hash=new String(input.array()).trim();
					hashlist.add(hash);
					System.out.println("Ricevuto hash: "+hash);
				}
			}
			return isTransactionValid(t,hashlist);
		}));*/
	}
	
	/**
	 * 	Checks whether a transaction 'merkleTx' is part of the merkle tree.
	 * 
	 *  @param merkleTx String: the transaction we want to validate
	 *  @param merkleNodes String: the hash codes of the merkle nodes required to compute 
	 *  the merkle root
	 *  
	 *  @return: boolean value indicating whether this transaction was validated or not.
	 * */
	private boolean isTransactionValid(String merkleTx, List<String> merkleNodes) {
		String result=merkleTx;
		for(String current:merkleNodes){
			result=HashUtil.md5Java(result.concat(current));
		}
		return result==mRoot;
	}

	/**
	 * Builder for the MerkleValidityRequest class. 
	 * */
	public static class Builder {
		private String authIPAddr;
		private int authPort;
		private String mRoot;
		private List<String> mRequest;	
		
		public Builder(String authorityIPAddr, int authorityPort, String merkleRoot) {
			this.authIPAddr = authorityIPAddr;
			this.authPort = authorityPort;
			this.mRoot = merkleRoot;
			mRequest = new ArrayList<>();
		}
				
		public Builder addMerkleValidityCheck(String merkleHash) {
			mRequest.add(merkleHash);
			return this;
		}
		
		public MerkleValidityRequest build() {
			return new MerkleValidityRequest(this);
		}
	}
}