{extends 'base.php'}
{block name="content"}
    <div class="jumbotron">
      <div class="container">
        <h1>Search</h1>
        <p>Search for status pages and services</p>
      </div>
    </div>
    <div class="row">
      <div class="col-md-8 col-md-offset-2">
        <form action="/search.php" method="get">
          <div class="input-group">
            <input type="text" class="form-control" name="q" placeholder="Search..." value="{$query nofilter}">
            <span class="input-group-btn">
              <button class="btn btn-signin" type="submit" style="background:#4f46e5;color:#fff;border:none;border-radius:0 6px 6px 0;font-weight:600;">Search</button>
            </span>
          </div>
        </form>
        {if !empty($query)}
        <hr>
        <h3>Search results for: {$query nofilter}</h3>
        {foreach $results as $r}
          <p>{$r}</p>
        {/foreach}
        {/if}
      </div>
    </div>
{/block}
