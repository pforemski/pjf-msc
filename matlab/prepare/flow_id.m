% get packet flow id
function fid = flow_id(id)

global PKT;

% lookup flow index
txt = sprintf('udp %u:%u -> %u:%u', PKT.srcip(id), PKT.srcport(id), PKT.dstip(id), PKT.dstport(id));
if isKey(PKT.flowmap, txt)
    fid = PKT.flowmap(txt);
else
    fid = size(PKT.flows, 2) + 1;
    PKT.flowmap(txt) = fid;
    
    PKT.flows(fid).type  = 'udp flow';
    PKT.flows(fid).ip    = [ PKT.srcip(id) PKT.dstip(id) ];
    PKT.flows(fid).port  = [ PKT.srcport(id) PKT.dstport(id) ];
    PKT.flows(fid).packets = [];
end
