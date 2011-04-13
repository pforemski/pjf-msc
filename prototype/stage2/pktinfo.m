% Group raw packet information into flows
% For each flow divide packets into windows
% For each window compute KISS signature + basic info
function pktinfo = pktinfo(pkts, b, N, C, dfl_label)

global PKT;

% KISS params
PKT.b = b;                % bits in byte
PKT.N = N;                % bytes in packets
PKT.G = (ceil(8/b) * N);  % number of groups in each packet
PKT.C = C;                % number of packets in window
PKT.K = 2 ^ b;            % number of counters in window
PKT.E = C / 2^b;          % expected number of occurances

% for easier reading
PKT.pktlabel = pkts(:, 1);
PKT.id = pkts(:, 2);
PKT.real_id = pkts(:, 3);
PKT.time = pkts(:, 4) * 1000000 + pkts(:, 5);
PKT.size = pkts(:, 6);
PKT.srcip = pkts(:, 7);
PKT.srcport = pkts(:, 8);
PKT.dstip = pkts(:, 9);
PKT.dstport = pkts(:, 10);
PKT.tcp = pkts(:, 11);
PKT.tcpseq = pkts(:, 12);
PKT.payload = pkts(:, 13:12 + PKT.G);

% label
if PKT.pktlabel == 0
    PKT.pktlabel = dfl_label;
end

% flow info
PKT.flowmap = containers.Map('KeyType', 'char', 'ValueType', 'uint32');
PKT.flows = [];

% collect packets into flows
for i = 1:size(pkts, 1)
    ep = epid(i);

    len = size(PKT.flows(ep).packets, 2) + 1;
    PKT.flows(ep).packets(len) = i;
    if (mod(len, C) == 0)
        pktwindow(ep);
    end
end

if ~isfield(PKT.flows, 'windows')
    error('no packet windows - dump too short?')
end

pktinfo = rmfield(PKT, {'flows' 'flowmap'});
pktinfo.flows = struct('ip', {}, 'port', {}, 'windows', {});

% copy only flows having at least one window
for i = 1:size(PKT.flows, 2)
    if size(PKT.flows(i).windows, 2) == 0
        continue
    end
    
    pktinfo.flows(end+1) = rmfield(PKT.flows(i), 'packets');
end
