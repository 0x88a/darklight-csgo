#include "gui.h"
#include "../../features/misc.h"

void GUI::Run()
{
	if (UTILS::KeyPressed(VK_DELETE) ||
		UTILS::KeyPressed(VK_INSERT))
	{
		m_bOpened = !m_bOpened;

		if (G::pLocal && !G::pLocal->IsAlive() || !I::Engine->IsInGame())
			I::InputSystem->EnableInput(!m_bOpened);

		C::Refresh();
	}

	static float flMenuAlpha = 0.0f;
	CONTROLS::m_flMenuAlpha = flMenuAlpha * 255.0f;

	if (!m_bOpened)
	{
		if (G::bTakingInput)
			G::bTakingInput = false;

		CONTROLS::m_bCloseBoxes = false;

		flMenuAlpha -= (1.0f / 0.2f) * I::Globals->flFrameTime;
		CONTROLS::uInfo.m_flAlpha = flMenuAlpha;
		if (flMenuAlpha <= 0.01f)
		{
			flMenuAlpha = 0.0f;
			return;
		}
	}
	else 
	{
		flMenuAlpha += (1.0f / 0.2f) * I::Globals->flFrameTime;
		if (flMenuAlpha >= 0.9f)
			flMenuAlpha = 1.0f;
	}

	CONTROLS::BeginWindow({ (float)C::Get<int>(Vars.iMenuX), (float)C::Get<int>(Vars.iMenuY)}, { (float)D::ScaleDPI(440), (float)D::ScaleDPI(520) });
	{
		switch (CONTROLS::m_iSelectedTab)
		{
		case 0: // LEGITBOT
		{
			static int iWeaponSelection = 0;
			static std::vector<std::string> vecWeaponSelection = { _("General"), _("Pistols"), _("Heavy pistols"), _("Rifles"), _("Shotguns"), _("SMGs"), _("Heavy"), _("Autos"), _("Scout"), _("AWP") };
			CONTROLS::BeginGroupbox(_("Aimbot"), C::Get<std::deque<bool>>(Vars.vecSilentEnable).at(iWeaponSelection) ? 294 : 264);
			{
				CONTROLS::Multibox(_("Enabled weapons"), vecWeaponSelection, &C::Get<std::deque<bool>>(Vars.vecWeaponEnabled));
				CONTROLS::Combobox(_("Selected weapon"), vecWeaponSelection, &iWeaponSelection);

				CONTROLS::Keybind(_("AIMBOT KEY"), &C::Get<int>(Vars.iAimbotKey), &C::Get<int>(Vars.iAimbotKeyMethod));
				CONTROLS::Checkbox(_("Enable"), &(C::Get<std::deque<bool>>(Vars.vecEnable)).at(iWeaponSelection));
				CONTROLS::Combobox(_("Preferred hitbox"), { _("Head"), _("Chest"), _("Pelvis"), _("Nearest") }, &(C::Get<std::deque<int>>(Vars.vecHitboxSelection)).at(iWeaponSelection));
				CONTROLS::Slider(_("FOV"), &(C::Get<std::deque<float>>(Vars.vecRegularFOV)).at(iWeaponSelection), 0.0f, 25.0f, "");
				CONTROLS::Checkbox(_("Silent aim"), &(C::Get<std::deque<bool>>(Vars.vecSilentEnable)).at(iWeaponSelection));
				if ((C::Get<std::deque<bool>>(Vars.vecSilentEnable)).at(iWeaponSelection))
					CONTROLS::Slider(_("Silent fov"), &(C::Get<std::deque<float>>(Vars.vecSilentFOV)).at(iWeaponSelection), 0.0f, 25.0f);
				CONTROLS::Slider(_("Smoothing"), &(C::Get<std::deque<float>>(Vars.vecSmoothing)).at(iWeaponSelection), 1.0f, 20.0f);
				CONTROLS::Slider(_("Recoil control"), &(C::Get<std::deque<float>>(Vars.vecRCS)).at(iWeaponSelection), 0.0f, 100.0f, "");
			}
			CONTROLS::EndGroupbox();

			CONTROLS::PopGroupboxY();

			CONTROLS::BeginGroupbox(_("Triggerbot"), 150, 1);
			{
				CONTROLS::Keybind(_("TRIGGERBOT  KEY"), &C::Get<int>(Vars.iTriggerbotKey), &C::Get<int>(Vars.iTriggerbotKeyMethod));
				CONTROLS::Checkbox(_("Enable#triggerbot"), &C::Get<bool>(Vars.bTriggerbot));
				CONTROLS::Slider(_("Reaction time"), &C::Get<int>(Vars.iTriggerbotDelay), 0, 200, "ms");
				CONTROLS::Slider(_("Minimum damage"), &C::Get<float>(Vars.flTriggerbotMinDmg), 0, 100, "", true);
			}
			CONTROLS::EndGroupbox();
		}
		break;
		case 1: // RAGEBOT
		{
			static int iWeaponSelection = 0;
			static std::vector<std::string> vecWeaponSelection = { _("General"), _("Pistols"), _("Heavy pistols"), _("Rifles"), _("Shotguns"), _("SMGs"), _("Heavy"), _("Autos"), _("Scout"), _("AWP") };

			CONTROLS::BeginGroupbox(_("Aimbot- THIS IS EXPERIMENTAL"), 457);
			{
				C::Get<int>(Vars.iWeaponSelection) = iWeaponSelection;

				CONTROLS::Multibox(_("Enabled weapons"), vecWeaponSelection, &C::Get<std::deque<bool>>(Vars.vecRagebotWeaponEnabled));
				CONTROLS::Combobox(_("Selected weapon"), vecWeaponSelection, &iWeaponSelection);

				CONTROLS::Keybind(_("RAGEBOT KEY"), &C::Get<int>(Vars.iRagebotKey), &C::Get<int>(Vars.iRagebotKeyMethod));
				CONTROLS::Checkbox(_("Enable#ragebot"), &C::Get<bool>(Vars.bRagebotEnabled));

				switch (FNV1A::HashConst(vecWeaponSelection.at(iWeaponSelection).c_str()))
				{
				case FNV1A::HashConst(("General")):
					CONTROLS::Multibox(_("Hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes0));
					CONTROLS::Multibox(_("Multipoint hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes0));
					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes0).at(0))
						CONTROLS::Slider(_("Head pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");

					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes0).at(1) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes0).at(2) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes0).at(3) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes0).at(4) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes0).at(5) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes0).at(6))
						CONTROLS::Slider(_("Body pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");
					break;
				case FNV1A::HashConst(("Pistols")):
					CONTROLS::Multibox(_("Hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes01));
					CONTROLS::Multibox(_("Multipoint hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes01));
					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes01).at(0))
						CONTROLS::Slider(_("Head pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");

					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes01).at(1) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes01).at(2) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes01).at(3) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes01).at(4) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes01).at(5) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes01).at(6))
						CONTROLS::Slider(_("Body pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");
					break;
				case FNV1A::HashConst(("Heavy pistols")):
					CONTROLS::Multibox(_("Hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes02));
					CONTROLS::Multibox(_("Multipoint hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes02));
					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes02).at(0))
						CONTROLS::Slider(_("Head pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");

					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes02).at(1) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes02).at(2) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes02).at(3) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes02).at(4) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes02).at(5) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes02).at(6))
						CONTROLS::Slider(_("Body pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");
					break;
				case FNV1A::HashConst(("Rifles")):
					CONTROLS::Multibox(_("Hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes03));
					CONTROLS::Multibox(_("Multipoint hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes03));
					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes03).at(0))
						CONTROLS::Slider(_("Head pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");

					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes03).at(1) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes03).at(2) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes03).at(3) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes03).at(4) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes03).at(5) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes03).at(6))
						CONTROLS::Slider(_("Body pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");
					break;
				case FNV1A::HashConst(("Shotguns")):
					CONTROLS::Multibox(_("Hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes04));
					CONTROLS::Multibox(_("Multipoint hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes04));
					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes04).at(0))
						CONTROLS::Slider(_("Head pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");

					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes04).at(1) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes04).at(2) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes04).at(3) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes04).at(4) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes04).at(5) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes04).at(6))
						CONTROLS::Slider(_("Body pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");
					break;
				case FNV1A::HashConst(("SMGs")):
					CONTROLS::Multibox(_("Hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes05));
					CONTROLS::Multibox(_("Multipoint hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes05));
					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes05).at(0))
						CONTROLS::Slider(_("Head pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");

					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes05).at(1) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes05).at(2) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes05).at(3) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes05).at(4) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes05).at(5) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes05).at(6))
						CONTROLS::Slider(_("Body pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");
					break;
				case FNV1A::HashConst(("Heavy")):
					CONTROLS::Multibox(_("Hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes06));
					CONTROLS::Multibox(_("Multipoint hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes06));
					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes06).at(0))
						CONTROLS::Slider(_("Head pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");

					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes06).at(1) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes06).at(2) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes06).at(3) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes06).at(4) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes06).at(5) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes06).at(6))
						CONTROLS::Slider(_("Body pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");
					break;
				case FNV1A::HashConst(("Autos")):
					CONTROLS::Multibox(_("Hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes07));
					CONTROLS::Multibox(_("Multipoint hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes07));
					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes07).at(0))
						CONTROLS::Slider(_("Head pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");

					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes07).at(1) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes07).at(2) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes07).at(3) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes07).at(4) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes07).at(5) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes07).at(6))
						CONTROLS::Slider(_("Body pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");
					break;
				case FNV1A::HashConst(("Scout")):
					CONTROLS::Multibox(_("Hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes08));
					CONTROLS::Multibox(_("Multipoint hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes08));
					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes08).at(0))
						CONTROLS::Slider(_("Head pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");

					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes08).at(1) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes08).at(2) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes08).at(3) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes08).at(4) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes08).at(5) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes08).at(6))
						CONTROLS::Slider(_("Body pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");
					break;
				case FNV1A::HashConst(("Auto")):
					CONTROLS::Multibox(_("Hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes09));
					CONTROLS::Multibox(_("Multipoint hitboxes"), { _("Head"), _("Chest"), _("Arms"), _("Stomach"), _("Pelvis"), _("Legs"), _("Feet") }, &C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes09));
					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes09).at(0))
						CONTROLS::Slider(_("Head pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");

					if (C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes09).at(1) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes09).at(2) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes09).at(3) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes09).at(4) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes09).at(5) ||
						C::Get<std::deque<bool>>(Vars.vecRagebotMultipointHitboxes09).at(6))
						CONTROLS::Slider(_("Body pointscale"), &(C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead)).at(iWeaponSelection), 0.0f, 100.0f, "");
					break;
				}

				Vars.vecRagebotHitboxes[0] = C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes0);
				Vars.vecRagebotHitboxes[1] = C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes01);
				Vars.vecRagebotHitboxes[2] = C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes02);
				Vars.vecRagebotHitboxes[3] = C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes03);
				Vars.vecRagebotHitboxes[4] = C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes04);
				Vars.vecRagebotHitboxes[5] = C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes05);
				Vars.vecRagebotHitboxes[6] = C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes06);
				Vars.vecRagebotHitboxes[7] = C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes07);
				Vars.vecRagebotHitboxes[8] = C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes08);
				Vars.vecRagebotHitboxes[9] = C::Get<std::deque<bool>>(Vars.vecRagebotHitboxes09);

				CONTROLS::Slider(_("Hitchance"), &(C::Get<std::deque<float>>(Vars.vecRagebotHitchance)).at(iWeaponSelection), 0.0f, 100.0f, "");

				CONTROLS::Checkbox(_("Silent aim"), &(C::Get<std::deque<bool>>(Vars.vecRagebotSilentEnable)).at(iWeaponSelection));
				CONTROLS::Checkbox(_("Automatic penetration"), &(C::Get<std::deque<bool>>(Vars.vecRagebotMindamage)).at(iWeaponSelection));
				if (C::Get<std::deque<bool>>(Vars.vecRagebotMindamage).at(iWeaponSelection))
					CONTROLS::Slider(_("Minimum damage"), &(C::Get<std::deque<float>>(Vars.vecRagebotMindamageValue)).at(iWeaponSelection), 0.0f, 125.0f, "", true);

				CONTROLS::Slider(_("FOV"), &(C::Get<std::deque<float>>(Vars.vecRagebotRegularFOV)).at(iWeaponSelection), 0.0f, 180.0f, "");
			}
			CONTROLS::EndGroupbox();

			CONTROLS::PopGroupboxY();

			static bool enabled = false;
			static int base = 0;
			static int yaw = 0;
			static int fake = 0;
			static int yaw_additive = 0;
			static int fake_max = 0;
			static int body_yaw = 0;
			static bool freestanding_body_yaw = 0;
			static int body_yaw_additive = 0;
			CONTROLS::BeginGroupbox(_("Anti-aim"), 302, 1);
			{
				CONTROLS::Checkbox("Enabled", &enabled);
				CONTROLS::Combobox("Yaw base", { "Off", "Local view", "At targets" }, & base);
				CONTROLS::Combobox("Yaw", { "Off", "180", "180z", "Spin", "Jitter" }, & yaw);
				if (yaw > 0)
					CONTROLS::Slider("Yaw additive", &yaw_additive, -180, 180, "");

				CONTROLS::Combobox("Fake type", { "Off", "Opposite", "Eye yaw" }, & fake);
				if (fake > 0)
					CONTROLS::Slider("Max fake", &fake_max, 0, 60, "");

				CONTROLS::Combobox("Body yaw", { "Opposite", "Jitter", "Static" }, & body_yaw);
				if (body_yaw > 0)
				{
					CONTROLS::Slider("Body yaw additive", &body_yaw_additive, -180, 180, "");
					CONTROLS::Checkbox("Freestand body yaw", &freestanding_body_yaw);
				}
			}
			CONTROLS::EndGroupbox();

			CONTROLS::BeginGroupbox(_("Fake-lag"), 147, 1);
			{

			}
			CONTROLS::EndGroupbox();
		} 
		break;
		case 2: // PLAYERS
		{
			CONTROLS::BeginGroupbox(_("Players"), 150);
			{
				CONTROLS::Colorpicker(_("box_col"), &C::Get<Color>(Vars.colBox), &C::Get<Color>(Vars.colBox).arrColor.at(3), true, true);
				CONTROLS::Checkbox(_("Box"), &C::Get<bool>(Vars.bBox));
				CONTROLS::Colorpicker(_("name_col"), &C::Get<Color>(Vars.colName), &C::Get<Color>(Vars.colName).arrColor.at(3), true, true);
				CONTROLS::Checkbox(_("Name"), &C::Get<bool>(Vars.bName));
				CONTROLS::Checkbox(_("Health"), &C::Get<bool>(Vars.bHealth));
				CONTROLS::Colorpicker(_("weapon_col"), &C::Get<Color>(Vars.colWeapon), &C::Get<Color>(Vars.colWeapon).arrColor.at(3), true, true);
				CONTROLS::Checkbox(_("Weapon"), &C::Get<bool>(Vars.bWeapon));
				CONTROLS::Colorpicker(_("ammo_col"), &C::Get<Color>(Vars.colAmmo), &C::Get<Color>(Vars.colAmmo).arrColor.at(3), true, true);
				CONTROLS::Checkbox(_("Ammo"), &C::Get<bool>(Vars.bAmmo));
				CONTROLS::Colorpicker(_("glow_col"), &C::Get<Color>(Vars.colGlow), &C::Get<Color>(Vars.colGlow).arrColor.at(3), true, true);
				CONTROLS::Checkbox(_("Glow"), &C::Get<bool>(Vars.bGlow));

				CONTROLS::Slider(_("Dormancy"), &C::Get<float>(Vars.flDormancy), 0.0f, 10.0f, "s");
			}
			CONTROLS::EndGroupbox();
				
			CONTROLS::PopGroupboxY();
				
			CONTROLS::BeginGroupbox(_("Chams"), 160, 1);
			{
				CONTROLS::Colorpicker(_("chams_col"), &C::Get<Color>(Vars.colChams), &C::Get<Color>(Vars.colChams).arrColor.at(3), true, true);
				CONTROLS::Checkbox(_("Visible"), &C::Get<bool>(Vars.bChams));
				CONTROLS::Colorpicker(_("xqz_col"), &C::Get<Color>(Vars.colChamsXQZ), &C::Get<Color>(Vars.colChamsXQZ).arrColor.at(3), true, true);
				CONTROLS::Checkbox(_("Invisible"), &C::Get<bool>(Vars.bChamsXQZ));
				CONTROLS::Checkbox(_("Disable occlusion"), &C::Get<bool>(Vars.bExtendChams));
				CONTROLS::Colorpicker(_("sleeve_col"), &C::Get<Color>(Vars.colSleeve), &C::Get<Color>(Vars.colSleeve).arrColor.at(3), true, true);
				CONTROLS::Checkbox(_("Sleeve Chams"), &C::Get<bool>(Vars.bSleeve));

				CONTROLS::Checkbox(_("Flat material"), &C::Get<bool>(Vars.bFlat));
				
				CONTROLS::Colorpicker(_("phong_col"), &C::Get<Color>(Vars.colPhong), &C::Get<Color>(Vars.colPhong).arrColor.at(3), true, true);
				CONTROLS::Checkbox(_("Shine"), &C::Get<bool>(Vars.bPhong));

				CONTROLS::Colorpicker(_("reflecitivty_col"), &C::Get<Color>(Vars.colReflectivity), &C::Get<Color>(Vars.colReflectivity).arrColor.at(3), false, true);
				CONTROLS::Checkbox(_("Reflectivity"), &C::Get<bool>(Vars.bReflectivity));

				CONTROLS::Slider(_("Pearlescent"), &C::Get<float>(Vars.flPearlescent), 0, 100, "");
			}
			CONTROLS::EndGroupbox();

			CONTROLS::BeginGroupbox(_("ESP Preview"), 280, 0);

			Vector2D m_vPlacement = { CONTROLS::m_vOffset.x + 20, CONTROLS::m_vOffset.y };
			Vector2D m_vBoxSize = { 150, 230 };


			if (C::Get<bool>(Vars.bName)) {

				auto name_text_size = D::GetTextSize(D::uVerdana[G::iDPIScale], "Name");
				D::String((int)m_vPlacement.x + (m_vBoxSize.x / 2) - (name_text_size.right / 2), (int)m_vPlacement.y, D::uVerdana[G::iDPIScale], "Name", false, Color(C::Get<Color>(Vars.colName)));
			}
			
			if (C::Get<bool>(Vars.bBox)) {	

				D::OutlinedRect((int)m_vPlacement.x, (int)m_vPlacement.y + 14, m_vBoxSize.x, m_vBoxSize.y, Color(C::Get<Color>(Vars.colBox)));
				D::OutlinedRect((int)m_vPlacement.x - 1, (int)m_vPlacement.y + 13, 152, 232, Color(0, 0, 0, 255));
				D::OutlinedRect((int)m_vPlacement.x + 1, (int)m_vPlacement.y + 15, 148, 228, Color(0, 0, 0, 255));
			}

			if (C::Get<bool>(Vars.bHealth)) {

				/* Match our color */
				auto green = 100 * 2.55;
				auto red = 255 - green;

				D::Rect((int)m_vPlacement.x - 6, (int)m_vPlacement.y + 13, 2, m_vBoxSize.y + 2, Color(80, 80, 80, 125)); // not really needed as its covered, you can keep if you want to add a animation later
				D::Rect((int)m_vPlacement.x - 6, (int)m_vPlacement.y + 13, 2, m_vBoxSize.y + 2, Color(red, green, 0, 255));
				D::OutlinedRect((int)m_vPlacement.x - 7, (int)m_vPlacement.y + 13, 4, m_vBoxSize.y + 2, Color(0, 0, 0, 255));
			}

			if (C::Get<bool>(Vars.bWeapon)) {

				auto weapon_text_size = D::GetTextSize(D::uSmallFonts[G::iDPIScale], "WEAPON");
				D::String((int)m_vPlacement.x + (m_vBoxSize.x / 2) - (weapon_text_size.right / 2), (int)m_vPlacement.y + (int)m_vBoxSize.y + 15, D::uSmallFonts[G::iDPIScale], "WEAPON", false, Color(C::Get<Color>(Vars.colWeapon)));
			}

			CONTROLS::EndGroupbox();
		}
		break;
		case 3: // VISUALS
		{
			CONTROLS::BeginGroupbox(_("Others"), 105);
			{
				CONTROLS::Colorpicker(_("dropped_weapon_name"), &C::Get<Color>(Vars.colDroppedWeaponName), &C::Get<Color>(Vars.colDroppedWeaponName).arrColor.at(3), true, true);
				CONTROLS::Checkbox(_("Dropped name"), &C::Get<bool>(Vars.bDroppedWeaponName));

				CONTROLS::Colorpicker(_("dropped_weapon_ammo"), &C::Get<Color>(Vars.colDroppedWeaponAmmo), &C::Get<Color>(Vars.colDroppedWeaponAmmo).arrColor.at(3), true, true);
				CONTROLS::Checkbox(_("Dropped ammo"), &C::Get<bool>(Vars.bDroppedWeaponAmmo));

				CONTROLS::Colorpicker(_("grenades_col"), &C::Get<Color>(Vars.colGrenades), &C::Get<Color>(Vars.colGrenades).arrColor.at(3), true, true);
				CONTROLS::Checkbox(_("Grenades"), &C::Get<bool>(Vars.bGrenades));

				CONTROLS::Colorpicker(_("timer_col"), &C::Get<Color>(Vars.colGrenadeTimer), &C::Get<Color>(Vars.colGrenadeTimer).arrColor.at(3), true, true);
				CONTROLS::Checkbox(_("Grenade timer"), &C::Get<bool>(Vars.bGrenadeTimer));

				CONTROLS::Checkbox(_("C4 timer"), &C::Get<bool>(Vars.bBombTimer));
			}
			CONTROLS::EndGroupbox();

			CONTROLS::PopGroupboxY();

			CONTROLS::BeginGroupbox(_("Misc"), 170, 1);
			{
				CONTROLS::Checkbox(_("Radar"), &C::Get<bool>(Vars.bRadarHack));

				//CONTROLS::Colorpicker(_("nightmode_col"), &C::Get<Color>(Vars.colNightmode), &C::Get<Color>(Vars.colNightmode).arrColor.at(3), false, true);
				//CONTROLS::Checkbox(_("Nightmode"), &C::Get<bool>(Vars.bNightmode));

				CONTROLS::Colorpicker(_("grenade_prediction"), &C::Get<Color>(Vars.colGrenadePrediction), &C::Get<Color>(Vars.colGrenadePrediction).arrColor.at(3), false, true);
				CONTROLS::Checkbox(_("Grenade prediction"), &C::Get<bool>(Vars.bGrenadePrediction));

				CONTROLS::Checkbox(_("Spectator list"), &C::Get<bool>(Vars.bSpectatorList));
				CONTROLS::Checkbox(_("Hitmarker"), &C::Get<bool>(Vars.bHitmarker));

				CONTROLS::Checkbox(_("Sniper crosshair"), &C::Get<bool>(Vars.bSniperCrosshair));
				CONTROLS::Checkbox(_("Recoil crosshair"), &C::Get<bool>(Vars.bRecoilCrosshair));

				CONTROLS::Keybind(_("flashlight_bind"), &C::Get<int>(Vars.iFlashlightKey), &C::Get<int>(Vars.iFlashlightKeyMethod));
				CONTROLS::Checkbox(_("Flashlight"), &C::Get<bool>(Vars.bFlashlight));

				CONTROLS::Checkbox(_("FOV Changer"), &C::Get<bool>(Vars.bFOVChanger));
				if (C::Get<bool>(Vars.bFOVChanger))
				{
					CONTROLS::Slider(_("Viewmodel FOV"), &C::Get<float>(Vars.flPlayerFOV), -89.f, 89.f, "");
				}

			}
			CONTROLS::EndGroupbox();

			CONTROLS::BeginGroupbox(_("Movement"), C::Get<bool>(Vars.bVelocityGraph) ? 170 : 85, 1);
			{
				
				CONTROLS::Checkbox(_("Velocity indicators"), &C::Get<bool>(Vars.bVelocityIndicators));
				CONTROLS::Checkbox(_("Velocity graph"), &C::Get<bool>(Vars.bVelocityGraph));
				if (C::Get<bool>(Vars.bVelocityGraph))
				{
					CONTROLS::Slider(_("Width"), &C::Get<int>(Vars.iVelocityGraphWidth), 100, 1000, "");
					CONTROLS::Slider(_("Compression"), &C::Get<float>(Vars.flVelocityGraphCompression), 1.0f, 10.0f, "");
					CONTROLS::Slider(_("Position additive"), &C::Get<int>(Vars.iYAdditive), 0, 500, "");
				}
				CONTROLS::Checkbox(_("Bug indicators"), &C::Get<bool>(Vars.bBugIndicators));
				CONTROLS::Checkbox(_("Keystrokes"), &C::Get<bool>(Vars.bKeystrokes));
			}
			CONTROLS::EndGroupbox();
		}
		break;
		case 4: // MISC
		{
			CONTROLS::BeginGroupbox(_("Misc"), C::Get<bool>(Vars.bBacktrack) ? 219 : 189);
			{
				CONTROLS::Multibox(_("Matchmaking"), { _("Unlock inventory"), _("Bypass sv_pure"), _("Auto accept"), _("Rank reveal") }, & C::Get<std::deque<bool>>(Vars.vecMatchmaking));
				CONTROLS::Multibox(_("Event logs"), { _("Damage given"), _("Damage recieved"), _("Weapon purchases"), _("Bomb info") }, & C::Get<std::deque<bool>>(Vars.vecEventLogs));
				CONTROLS::Checkbox(_("Clantag Spammer"), &C::Get<bool>(Vars.bClantagChanger));
				CONTROLS::Checkbox(_("Auto shoot"), &C::Get<bool>(Vars.bAutoShoot));
				CONTROLS::Colorpicker(_("custom_menu_col"), &CONTROLS::m_cMenuColor, &CONTROLS::m_cMenuColor.arrColor.at(3), false, true);
				CONTROLS::Checkbox(_("Menu color"), &C::Get<bool>(Vars.bCustomMenuCol));
				CONTROLS::Checkbox(_("Watermark"), &C::Get<bool>(Vars.bWatermark));
				CONTROLS::Checkbox(_("Backtrack"), &C::Get<bool>(Vars.bBacktrack));
				if (C::Get<bool>(Vars.bBacktrack))
					CONTROLS::Slider(_("Max ticks"), &C::Get<int>(Vars.iBacktrackMax), 0, 12, "");
			}
			CONTROLS::EndGroupbox();

			CONTROLS::BeginGroupbox(_("Movement"), C::Get<int>(Vars.iBunnyHop) == 2 ? 211 : 181);
			{
				CONTROLS::Checkbox(_("Null strafer"), &C::Get<bool>(Vars.bNullStrafe));

				CONTROLS::Combobox(_("Bunnyhop"), { _("Off"), _("Perfect"), _("Legit") }, &C::Get<int>(Vars.iBunnyHop));
				if (C::Get<int>(Vars.iBunnyHop) == 2)
					CONTROLS::Slider(_("Bunnyhop hitchance"), &C::Get<float>(Vars.flBunnyhopHitchance), 0.0f, 100.0f);

				CONTROLS::Checkbox(_("Infinite duck"), &C::Get<bool>(Vars.bFastDuck));

				CONTROLS::Keybind(_("EDGEJUMP_KEY"), &C::Get<int>(Vars.iEdgeJumpKey), &C::Get<int>(Vars.iEdgeJumpKeyMethod));
				CONTROLS::Checkbox(_("Edge jump"), &C::Get<bool>(Vars.bEdgeJump));

				CONTROLS::Keybind(_("JUMPBUG_KEY"), &C::Get<int>(Vars.iJumpBugKey), &C::Get<int>(Vars.iJumpBugKeyMethod));
				CONTROLS::Checkbox(_("Jump bug"), &C::Get<bool>(Vars.bJumpBug));

				CONTROLS::Keybind(_("EDGEBUG_KEY"), &C::Get<int>(Vars.iEdgeBugKey), &C::Get<int>(Vars.iEdgeBugKeyMethod));
				CONTROLS::Checkbox(_("Edge bug"), &C::Get<bool>(Vars.bEdgeBug));

				CONTROLS::Keybind(_("OPTIMIZER_KEY"), &C::Get<int>(Vars.iStrafeOptimizer_Key), &C::Get<int>(Vars.iStrafeOptimizer_Key_Method));
				CONTROLS::Checkbox(_("Strafe Optimizer"), &C::Get<bool>(Vars.bStrafeOptimizer_Enabeld));
				if (C::Get<bool>(Vars.bStrafeOptimizer_Enabeld))
				{
					CONTROLS::Slider(_("Min Speed"), &C::Get<int>(Vars.iStrafeOptimizer_Min_Speed), 200, 400, "");
					CONTROLS::Slider(_("Desired Gain"), &C::Get<int>(Vars.iStrafeOptimizer_Desired_Gain), 0, 100, "");
					
				}

				CONTROLS::Keybind(_("MINIJUMP_KEY"), &C::Get<int>(Vars.iMiniJump_Key), &C::Get<int>(Vars.iMiniJump_Key_Method));
				CONTROLS::Checkbox(_("Mini Jump"), &C::Get<bool>(Vars.bMiniJump));

				CONTROLS::Keybind(_("blockbot"), &C::Get<int>(Vars.iBlockbotKey), &C::Get<int>(Vars.iBlockbotKeyMethod));
				CONTROLS::Combobox(_("Blockbot"), { _("Off"), _("Match speed"), _("Maximum") }, &C::Get<int>(Vars.iBlockbot));
			}
			CONTROLS::EndGroupbox();
				
			CONTROLS::PopGroupboxY();
				
			CONTROLS::BeginGroupbox(_("Configs"), 202, 1);
			{
				static std::string pText = "New config";
				static int iConfigSelection = 0;
				std::vector<std::string> vConfig = { };
				for (auto i = 0; i < C::vecFileNames.size(); i++)
					vConfig.push_back(C::vecFileNames.at(i));
				
				CONTROLS::TextField(_("Config name"), &pText);
				
				if (!pText.empty())
				{
					CONTROLS::Button(_("Create"), [&]() {
						C::Save(pText);
						C::Refresh();
						g_Visuals.vecEventVector.push_back(EventLogging_t{ fmt::format(_("Created config {config}."), fmt::arg(_("config"), pText.c_str())) });
						I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("["));
						I::ConVar->ConsoleColorPrintf(Color(CONTROLS::m_cDefaultMenuCol), _("Darklight"));
						I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("]"));
						I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), fmt::format(_(" Created config {config}.\n"), fmt::arg(_("config"), pText.c_str())).c_str());
						});
				}
				
				if (!vConfig.empty())
				{
					CONTROLS::Button(_("Remove"), [&]() {
						C::Remove(vConfig.at(iConfigSelection));
						g_Visuals.vecEventVector.push_back(EventLogging_t{ fmt::format(_("Deleted config {config}."), fmt::arg(_("config"), vConfig.at(iConfigSelection).c_str())) });
						I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("["));
						I::ConVar->ConsoleColorPrintf(Color(CONTROLS::m_cDefaultMenuCol), _("Darklight"));
						I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("]"));
						I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), fmt::format(_(" Deleted config {config}.\n"), fmt::arg(_("config"), vConfig.at(iConfigSelection).c_str())).c_str());
						iConfigSelection = 0;
						C::Refresh();
						});
				
					CONTROLS::Combobox(_("Configs"), vConfig, &iConfigSelection);
				
					CONTROLS::Button(_("Save"), [&]() {
						C::Save(vConfig.at(iConfigSelection));
						g_Visuals.vecEventVector.push_back(EventLogging_t{ fmt::format(_("Saved config {config}."), fmt::arg(_("config"), vConfig.at(iConfigSelection).c_str())) });
						I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("["));
						I::ConVar->ConsoleColorPrintf(Color(CONTROLS::m_cDefaultMenuCol), _("Darklight"));
						I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("]"));
						I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), fmt::format(_(" Saved config {config}.\n"), fmt::arg(_("config"), vConfig.at(iConfigSelection).c_str())).c_str());
						});
				
					CONTROLS::Button(_("Load"), [&]() {
						C::Load(vConfig.at(iConfigSelection));
						U::ForceFullUpdate();
						g_Visuals.vecEventVector.push_back(EventLogging_t{ fmt::format(_("Loaded config {config}."), fmt::arg(_("config"), vConfig.at(iConfigSelection).c_str())) });
						I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("["));
						I::ConVar->ConsoleColorPrintf(Color(CONTROLS::m_cDefaultMenuCol), _("Darklight"));
						I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("]"));
						I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), fmt::format(_(" Loaded config {config}.\n"), fmt::arg(_("config"), vConfig.at(iConfigSelection).c_str())).c_str());
						});
				}
			}
			CONTROLS::EndGroupbox();

			CONTROLS::BeginGroupbox(_("Recorder"), 53 + 48, 1);
			{
				if (recorder.IsRecordingActive())
				{
					CONTROLS::Button("Stop Recording", [&]() {
						recorder.StopRecording();
						});
				}
				else if (recorder.IsRerecordingActive())
				{
					CONTROLS::Button("Save Re-recording", [&]() {
						recorder.StopRerecording(true);
						});

					CONTROLS::Button("Clear Re-recording", [&]() {
						recorder.StopRerecording();
						});
				}
				else {
					CONTROLS::Button("Start Recording", [&]() {
						recorder.StartRecording();
						});

					if (!recorder.GetActiveRecording().empty()) {
						CONTROLS::Button("Clear Recorded Frames", [&]() {
							recorder.GetActiveRecording().clear();
							});

						if (playback.IsPlaybackActive())
							CONTROLS::Button("Stop Playback", [&]() {
							playback.StopPlayback();
							g_Misc.m_bPreparedOrigin = false;
							g_Misc.m_bPreparedViewAngs = false;
							g_Misc.m_bMoveViewAngs = false;
								});
						else
							CONTROLS::Button("Start Playback", [&]() {
							playback.StartPlayback(recorder.GetActiveRecording());
								});
					}
				}
			}
			CONTROLS::EndGroupbox();
		}
		break;
		case 5: // SKINCHANGER
		{
			CONTROLS::BeginGroupbox(_("Other"), 168);
			{

				CONTROLS::Combobox(_("Knife model"), {
					_("Default"),
					_("Bayonet"),
					_("Flip knife"),
					_("Gut knife"),
					_("Karambit"),
					_("M9 bayonet"),
					_("Huntsman knife"),
					_("Falchion knife"),
					_("Bowie knife"),
					_("Butterfly knife"),
					_("Shadow daggers"),
					_("Ursus knife"),
					_("Navaja knife"),
					_("Stiletto knife"),
					_("Talon knife"),
					_("Classic knife"),
					_("Outdoor knife"),
					_("Skeleton knife"),
					_("Cord knife"),
					_("Canis knife")
					}, &C::Get<int>(Vars.iKnifeModel));

				static int iPrevKnife = 0;
				if (iPrevKnife != C::Get<int>(Vars.iKnifeModel))
				{
					iPrevKnife = C::Get<int>(Vars.iKnifeModel);
					U::ForceFullUpdate();
				}

				static std::vector<std::string> vecCTModels = {
					_("Default"),
"The Elite Mr. Muhlik",
	"Prof. Shahmat",
	"Osiris",
	"Ground Rebel",
	"Special Agent Ava",
	"Michael Syfers",
	"Markus Delrow",
	"Operator",
	"Seal Team 6 Soldier",
	"'Two Times' McCoy",
	"Buckshot",
	"3rd Commando Company",
	"Lt. Commander Ricksaw",
	"'Blueberries' Buckshot",
	"'Two Times' McCoy",
	"Cmdr. Mae 'Dead Cold' Jamison",
	"1st Lieutenant Farlow",
	"John 'Van Healen' Kask",
	"Bio-Haz Specialist",
	"Sergeant Bombson",
	"Chem-Haz Specialist",
	"Maximus ",
	"Dragomir",
	"The Doctor' Romanov",
	"Rezan The Ready",
	"Blackwolf",
	"Rezan the Redshirt",
	"Dragomir",
	"B Squadron Officer",
	"Soldier",
	"Enforcer",
	"Slingshot",
	"Street Soldier",
	"Miami Darryl",
	"Silent Darryl",
	"Skullhead Darryl",
	"Darryl Royale",
	"Loudmouth Darryl",
	"Safecracker Voltzmann",
	"Little Kev",
	"Number K",
	"Getaway Sally"
				};

				static std::vector<std::string> vecTModels = {
"The Elite Mr. Muhlik",
	"Prof. Shahmat",
	"Osiris",
	"Ground Rebel",
	"Special Agent Ava",
	"Michael Syfers",
	"Markus Delrow",
	"Operator",
	"Seal Team 6 Soldier",
	"'Two Times' McCoy",
	"Buckshot",
	"3rd Commando Company",
	"Lt. Commander Ricksaw",
	"'Blueberries' Buckshot",
	"'Two Times' McCoy",
	"Cmdr. Mae 'Dead Cold' Jamison",
	"1st Lieutenant Farlow",
	"John 'Van Healen' Kask",
	"Bio-Haz Specialist",
	"Sergeant Bombson",
	"Chem-Haz Specialist",
	"Maximus ",
	"Dragomir",
	"The Doctor' Romanov",
	"Rezan The Ready",
	"Blackwolf",
	"Rezan the Redshirt",
	"Dragomir",
	"B Squadron Officer",
	"Soldier",
	"Enforcer",
	"Slingshot",
	"Street Soldier",
	"Miami Darryl",
	"Silent Darryl",
	"Skullhead Darryl",
	"Darryl Royale",
	"Loudmouth Darryl",
	"Safecracker Voltzmann",
	"Little Kev",
	"Number K",
	"Getaway Sally"
				};

				CONTROLS::Combobox(_("CT Model"), vecCTModels, &C::Get<int>(Vars.iPlayerCTModel));
				CONTROLS::Combobox(_("T Model"), vecTModels, &C::Get<int>(Vars.iPlayerTModel));
			}
			CONTROLS::EndGroupbox();

			CONTROLS::BeginGroupbox(_("Gloves"), 166);
			{
				CONTROLS::Combobox(_("Glove model"), {
					_("Default"),
					_("Bloodhound"),
					_("Sporty"),
					_("Slick"),
					_("Handwrap"),
					_("Motorcycle"),
					_("Specialist"),
					_("Hydra"),
					_("Broken fang")
					}, &C::Get<int>(Vars.iGloveModel));

				CONTROLS::NumberField(_("Glove skin"), &(C::Get<std::deque<std::string>>(Vars.vecGloveSkins)).at(C::Get<int>(Vars.iGloveModel)));
				CONTROLS::Slider(_("Glove wear"), &(C::Get<std::deque<float>>(Vars.vecGloveWear)).at(C::Get<int>(Vars.iGloveModel)), 0.0f, 1.0f, "");
				CONTROLS::Slider(_("Glove seed"), &(C::Get<std::deque<int>>(Vars.vecGloveSeed)).at(C::Get<int>(Vars.iGloveModel)), 0, 100, "");
			}
			CONTROLS::EndGroupbox();

			CONTROLS::PopGroupboxY();

			CBaseEntity* pLocal = U::GetLocalPlayer();
			if (pLocal)
			{
				CBaseCombatWeapon* pWeapon = pLocal->GetWeapon();
				if (pWeapon && pWeapon->GetWeaponNameVerdana() != _("ERROR"))
				{
					CONTROLS::BeginGroupbox(pWeapon->GetWeaponNameVerdana() + _(" settings"), 128, 1);
					{
						CONTROLS::NumberField(_("Skin ID"), &(C::Get<std::deque<std::string>>(Vars.vecSkinIDs)).at(*pWeapon->GetItemDefinitionIndex()));
						CONTROLS::Slider(_("Wear"), &(C::Get<std::deque<float>>(Vars.vecSkinWear)).at(*pWeapon->GetItemDefinitionIndex()), 0.0f, 1.0f, "");
						CONTROLS::Slider(_("Seed"), &(C::Get<std::deque<int>>(Vars.vecSkinSeed)).at(*pWeapon->GetItemDefinitionIndex()), 0, 1000, "");
					}
					CONTROLS::EndGroupbox();
				}
			}
		} 
		break;
		default:
			break;
		}
	}
	CONTROLS::EndWindow();
}
