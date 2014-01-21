package com.devadvance.rootcloak;

import android.os.Bundle;
import android.annotation.SuppressLint;
import android.app.AlertDialog;
import android.app.ListActivity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.res.Resources;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.Toast;

public class SettingsActivity extends ListActivity {
	SharedPreferences sharedPref;
	String[] menuItems;
	String instructionsString;
	String instructionsTitle;

	@SuppressLint("WorldReadableFiles")
	@SuppressWarnings("deprecation")
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_settings);

		Resources res = getResources();
		menuItems = res.getStringArray(R.array.menu_array);
		instructionsString = res.getString(R.string.instructions1) + "\n\n"
				+ res.getString(R.string.instructions2) + "\n\n"
				+ res.getString(R.string.instructions3) + "\n\n"
				+ res.getString(R.string.instructions4);

		instructionsTitle = res.getString(R.string.instructions_title);
		
		ArrayAdapter<String> adapter = new ArrayAdapter<String>(this,
				android.R.layout.simple_list_item_1, menuItems);
		setListAdapter(adapter);

		sharedPref = getSharedPreferences(Common.PREFS_APPS, MODE_WORLD_READABLE);
		
		//todo put this in the proper location
		setLibPath();
	}
	
	void setLibPath() {
		String libpath = getApplication().getApplicationInfo().nativeLibraryDir + Common.LIB_SO_NAME;
		Log.d(Common.PACKAGE_NAME, "Setting libpath : " + libpath);
		Editor editor = sharedPref.edit();
		editor.remove(Common.PACKAGE_NAME + Common.LIB_NAME);
		editor.commit();
		editor.putString(Common.PACKAGE_NAME + Common.LIB_NAME, libpath);
		editor.commit();
	}
	
	public void onListItemClick(ListView parent, View v, int position, long id) {
		Intent intent;
		switch (position) {
		case 0:
			intent = new Intent(this, CustomizeApps.class);
			startActivity(intent);
			break;
		case 1:
			intent = new Intent(this, CustomizeKeywords.class);
			startActivity(intent);
			break;
		case 2:
			intent = new Intent(this, CustomizeCommands.class);
			startActivity(intent);
			break;
		case 3:
			Log.d(Common.PACKAGE_NAME, "Debug is now on");
			new AlertDialog.Builder(this)
					.setMessage(instructionsString)
					.setTitle(instructionsTitle).show();
			break;
		case 4:
			boolean debugPref = sharedPref.getBoolean(Common.PACKAGE_NAME
					+ Common.DEBUG_KEY, false);
			debugPref = !debugPref;
			Editor editor = sharedPref.edit();
			editor.remove(Common.PACKAGE_NAME + Common.DEBUG_KEY);
			editor.commit();
			editor.putBoolean(Common.PACKAGE_NAME + Common.DEBUG_KEY, debugPref);
			editor.commit();
			String debugStatus = "off";
			if (debugPref) {
				Log.d(Common.PACKAGE_NAME, "Debug is now on");
				debugStatus = "on";
			}
			Toast.makeText(getApplicationContext(),
					"Debug logcat messages are now " + debugStatus + ".",
					Toast.LENGTH_LONG).show();
			break;
		default:
			break;
		}
	}
}
