'use strict';
importScripts('hash.js');
self.onmessage=async function(event){
 try {const file=event.data.file, hash=new SHA256(), chunk=1024*1024;
 for(let start=0;start<file.size;start+=chunk){const blob=file.slice(start,start+chunk);let buffer;if(blob.arrayBuffer)buffer=await blob.arrayBuffer();else buffer=new FileReaderSync().readAsArrayBuffer(blob);hash.update(new Uint8Array(buffer));self.postMessage({progress:Math.min(1,(start+chunk)/file.size)});}
 self.postMessage({hash:hash.digestHex()});
 }catch(error){self.postMessage({error:String(error.message||error)});}
};
