function wid = window(fid)
global PKT;

% shortcut to flow info
finfo = PKT.flows(fid);

%
% collect packet info
%
winfo.packets = finfo.packets;
winfo.avgsize = round(mean(PKT.size(winfo.packets)));

% inter-packet time analysis
timediff = diff(PKT.time(winfo.packets));
timediff(timediff > quantile(timediff, 0.90)) = NaN;
winfo.avgtimespace = nanmean(timediff);
winfo.jitter = nanmean(abs(diff(timediff)));

% window duration, bitrate
winfo.duration = PKT.time(winfo.packets(end)) - PKT.time(winfo.packets(1));
winfo.bytes = sum(PKT.size(winfo.packets));
winfo.pps = 1000000 * PKT.C / winfo.duration;
winfo.kbps = (winfo.bytes * 8000) / winfo.duration;

%
% compute KISS signature
%
values = histc(PKT.payload(winfo.packets,:), 0:PKT.K - 1);  % count column-wise
winfo.signature = sum((values - PKT.E) .^ 2 ./ PKT.E);      % Chi-Square test

% write back to flow info
if ~isfield(finfo, 'windows')
	wid = 1;
else
    wid = size(finfo.windows, 2) + 1;
end

PKT.flows(fid).windows(wid) = winfo;
PKT.flows(fid).packets = [];
